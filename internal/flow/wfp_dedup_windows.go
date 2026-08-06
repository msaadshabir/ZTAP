//go:build windows

package flow

// wfpDedupKey is a comparable key for deduplicating WFP net events.
//
// We include FilterId + LayerId to avoid collapsing unrelated events that share
// a 5-tuple, while still reducing repeated emits from the same classify path.
type wfpDedupKey struct {
	srcIP    [4]uint32
	dstIP    [4]uint32
	srcPort  uint16
	dstPort  uint16
	protocol uint8
	dir      uint8
	action   uint8
	family   uint8

	filterID uint64
	layerID  uint16
}

func wfpDedupKeyFrom(ev wfpEvent, raw RawFlowEvent) wfpDedupKey {
	return wfpDedupKey{
		srcIP:    raw.SrcIP,
		dstIP:    raw.DestIP,
		srcPort:  raw.SrcPort,
		dstPort:  raw.DestPort,
		protocol: raw.Protocol,
		dir:      raw.Direction,
		action:   raw.Action,
		family:   raw.Family,
		filterID: ev.filterID,
		layerID:  ev.layerID,
	}
}

type wfpDeduper struct {
	windowNs uint64
	limit    int
	seen     map[wfpDedupKey]uint64
}

func newWfpDeduper(limit int, windowNs uint64) *wfpDeduper {
	if limit <= 0 {
		limit = 10000
	}
	if windowNs == 0 {
		windowNs = 250_000_000
	}
	return &wfpDeduper{
		windowNs: windowNs,
		limit:    limit,
		seen:     make(map[wfpDedupKey]uint64, limit),
	}
}

// SeenRecently returns true if the key was observed within the dedupe window.
//
// This is intentionally not concurrency-safe: WindowsReader calls it from a
// single worker goroutine.
func (d *wfpDeduper) SeenRecently(k wfpDedupKey, ts uint64) bool {
	if d == nil {
		return false
	}
	if d.limit > 0 && len(d.seen) >= d.limit {
		// Simple bound: clear map when it grows too large.
		d.seen = make(map[wfpDedupKey]uint64, d.limit)
	}

	if last, ok := d.seen[k]; ok {
		if ts >= last && ts-last <= d.windowNs {
			return true
		}
	}
	// Always store the latest timestamp.
	d.seen[k] = ts
	return false
}
