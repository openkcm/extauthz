package policy

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	cedar "github.com/cedar-policy/cedar-go"
)

type cedarEngine struct {
	policySet *cedar.PolicySet
}

// engineOption is used to configure an engine.
type engineOption func(*cedarEngine) error

// WithPath specifies the path to load policies from.
func WithPath(policyPath string) engineOption {
	return func(engine *cedarEngine) error {
		slog.Info("handling policy path", "name", policyPath)
		glob := filepath.Join(policyPath, "*.cedar")
		files, err := filepath.Glob(glob)
		if err != nil {
			return fmt.Errorf("failed to glob *.cedar policy files: %w", err)
		}
		for _, policyFile := range files {
			slog.Debug("handling policy file", "name", policyFile)
			policyBytes, err := os.ReadFile(policyFile)
			if err != nil {
				return fmt.Errorf("failed to read policy file: %w", err)
			}
			name := filepath.Base(policyFile)
			policyList, err := cedar.NewPolicyListFromBytes(name, policyBytes)
			if err != nil {
				return fmt.Errorf("failed to create policy set: %w", err)
			}
			for i, policy := range policyList {
				id := fmt.Sprintf("%s-%d", name, i)
				slog.Debug("adding policy", "id", id)
				engine.policySet.Add(cedar.PolicyID(id), policy)
			}
		}
		return nil
	}
}

// WithFile specifies the file to load policies from.
func WithFile(policyFile string) engineOption {
	return func(engine *cedarEngine) error {
		policyBytes, err := os.ReadFile(policyFile)
		if err != nil {
			return fmt.Errorf("failed to read policy file: %w", err)
		}
		return WithBytes(policyFile, policyBytes)(engine)
	}
}

// WithBytes specifies the bytes to load policies from.
func WithBytes(name string, policyBytes []byte) engineOption {
	return func(engine *cedarEngine) error {
		policyList, err := cedar.NewPolicyListFromBytes(name, policyBytes)
		if err != nil {
			return fmt.Errorf("failed to create policy set: %w", err)
		}
		for i, policy := range policyList {
			id := fmt.Sprintf("%s-%d", name, i)
			engine.policySet.Add(cedar.PolicyID(id), policy)
		}
		return nil
	}
}

func NewEngine(opts ...engineOption) (*cedarEngine, error) {
	engine := &cedarEngine{
		policySet: cedar.NewPolicySet(),
	}
	for _, opt := range opts {
		if err := opt(engine); err != nil {
			return nil, err
		}
	}
	return engine, nil
}
