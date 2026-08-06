//go:build windows

package enforcer

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"ztap/internal/logging"
)

var (
	activeWFPMu sync.Mutex
	wfpActive   bool
)

func wfpStrictModeEnabled() bool {
	return strings.TrimSpace(os.Getenv("ZTAP_WFP_STRICT")) == "1"
}

func wfpDefaultDenySpecs() []WFPSpec {
	return []WFPSpec{
		{
			Name:        "ZTAP-DefaultDeny-Egress-V4",
			Description: "Default deny egress (v4)",
			LayerKey:    LayerALEAuthConnectV4,
			SublayerKey: ZTAPSublayerGUID,
			ProviderKey: &ZTAPProviderGUID,
			Weight:      0,
			ActionType:  FWP_ACTION_BLOCK,
		},
		{
			Name:        "ZTAP-DefaultDeny-Egress-V6",
			Description: "Default deny egress (v6)",
			LayerKey:    LayerALEAuthConnectV6,
			SublayerKey: ZTAPSublayerGUID,
			ProviderKey: &ZTAPProviderGUID,
			Weight:      0,
			ActionType:  FWP_ACTION_BLOCK,
		},
		{
			Name:        "ZTAP-DefaultDeny-Ingress-V4",
			Description: "Default deny ingress (v4)",
			LayerKey:    LayerALEAuthRecvAcceptV4,
			SublayerKey: ZTAPSublayerGUID,
			ProviderKey: &ZTAPProviderGUID,
			Weight:      0,
			ActionType:  FWP_ACTION_BLOCK,
		},
		{
			Name:        "ZTAP-DefaultDeny-Ingress-V6",
			Description: "Default deny ingress (v6)",
			LayerKey:    LayerALEAuthRecvAcceptV6,
			SublayerKey: ZTAPSublayerGUID,
			ProviderKey: &ZTAPProviderGUID,
			Weight:      0,
			ActionType:  FWP_ACTION_BLOCK,
		},
	}
}

// EnforceWithWFP applies policies using Windows Filtering Platform.
func EnforceWithWFP(opts EnforcementOptions) error {
	activeWFPMu.Lock()
	defer activeWFPMu.Unlock()

	strict := wfpStrictModeEnabled()

	if opts.DryRun {
		logging.Info("[DRY-RUN] WFP: simulating policy translation and transaction", nil)
		if strict {
			logging.Info("[DRY-RUN] WFP: strict default-deny is enabled (ZTAP_WFP_STRICT=1)", nil)
		}
		for _, p := range opts.Policies {
			safeName := sanitizeForLog(p.Metadata.Name)
			specs, err := TranslatePolicyToWFP(p)
			if err != nil {
				logging.Warnf("[DRY-RUN] would skip policy '%s' due to translation error: %v", safeName, err)
				continue
			}
			logging.Infof("[DRY-RUN] WFP: would add %d filters for policy '%s'", len(specs), safeName)
		}
		wfpActive = true // Mark as active so dry-run Stop works
		return nil
	}

	engine := &realWFPEngine{}
	if err := engine.Open(); err != nil {
		return fmt.Errorf("failed to open WFP engine: %w", err)
	}
	defer engine.Close()

	if err := engine.BeginTransaction(); err != nil {
		return fmt.Errorf("failed to begin WFP transaction: %w", err)
	}

	// Ensure ZTAP provider and sublayer exist
	if err := engine.AddProvider("ZTAP", "Zero Trust Access Platform", &ZTAPProviderGUID); err != nil {
		engine.AbortTransaction()
		return fmt.Errorf("failed to add WFP provider: %w", err)
	}

	if err := engine.AddSublayer("ZTAP Policies", "ZTAP Managed Enforcement Sublayer", &ZTAPSublayerGUID, &ZTAPProviderGUID, 0); err != nil {
		engine.AbortTransaction()
		return fmt.Errorf("failed to add WFP sublayer: %w", err)
	}

	// Cleanup existing ZTAP filters before applying new ones
	if err := engine.DeleteFiltersByProvider(&ZTAPProviderGUID); err != nil {
		logging.Warnf("failed to cleanup old WFP filters: %v", err)
	}

	// Translate policies first so strict mode doesn't brick the host
	// if all translation fails.
	allSpecs := make([]WFPSpec, 0, len(opts.Policies))
	for _, p := range opts.Policies {
		safeName := sanitizeForLog(p.Metadata.Name)
		specs, err := TranslatePolicyToWFP(p)
		if err != nil {
			logging.Warnf("skipping policy '%s' due to translation error: %v", safeName, err)
			continue
		}
		allSpecs = append(allSpecs, specs...)
	}

	if strict && len(allSpecs) > 0 {
		for _, spec := range wfpDefaultDenySpecs() {
			if err := engine.AddFilter(&spec); err != nil {
				engine.AbortTransaction()
				return fmt.Errorf("failed to add WFP default deny filter: %w", err)
			}
		}
	}

	for _, spec := range allSpecs {
		if err := engine.AddFilter(&spec); err != nil {
			engine.AbortTransaction()
			return fmt.Errorf("failed to add WFP filter: %w", err)
		}
	}

	if err := engine.CommitTransaction(); err != nil {
		return fmt.Errorf("failed to commit WFP transaction: %w", err)
	}

	wfpActive = true
	return nil
}

// StopWFPEnforcement removes all ZTAP-managed WFP filters.
func StopWFPEnforcement() error {
	activeWFPMu.Lock()
	defer activeWFPMu.Unlock()

	if !wfpActive {
		return nil
	}

	engine := &realWFPEngine{}
	if err := engine.Open(); err != nil {
		return fmt.Errorf("failed to open WFP engine: %w", err)
	}
	defer engine.Close()

	if err := engine.BeginTransaction(); err != nil {
		return fmt.Errorf("failed to begin WFP transaction: %w", err)
	}

	if err := engine.DeleteFiltersByProvider(&ZTAPProviderGUID); err != nil {
		engine.AbortTransaction()
		return fmt.Errorf("failed to delete WFP filters: %w", err)
	}

	if err := engine.CommitTransaction(); err != nil {
		return fmt.Errorf("failed to commit WFP transaction: %w", err)
	}

	wfpActive = false
	return nil
}
