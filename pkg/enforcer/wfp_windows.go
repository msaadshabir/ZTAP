//go:build windows

package enforcer

import (
	"fmt"
	"log"
	"sync"

	"ztap/pkg/policy"
)

var (
	activeWFPMu sync.Mutex
	wfpActive   bool
)

// EnforceWithWFP applies policies using Windows Filtering Platform.
func EnforceWithWFP(policies []policy.NetworkPolicy) error {
	activeWFPMu.Lock()
	defer activeWFPMu.Unlock()

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
		log.Printf("Warning: failed to cleanup old WFP filters: %v", err)
	}

	// Translate and add filters
	for _, p := range policies {
		specs, err := TranslatePolicyToWFP(p)
		if err != nil {
			log.Printf("Warning: skipping policy '%s' due to translation error: %v", p.Metadata.Name, err)
			continue
		}

		for _, spec := range specs {
			if err := engine.AddFilter(&spec); err != nil {
				engine.AbortTransaction()
				return fmt.Errorf("failed to add WFP filter for policy '%s': %w", p.Metadata.Name, err)
			}
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
