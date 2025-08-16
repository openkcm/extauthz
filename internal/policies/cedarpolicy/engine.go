package cedarpolicy

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cedar-policy/cedar-go"
)

type cedarPolicyEngine struct {
	request cedar.Request

	policySet *cedar.PolicySet
}

// Option is used to configure an engine.
type Option func(*cedarPolicyEngine) error

func NewEngine(opts ...Option) (*cedarPolicyEngine, error) {
	engine := &cedarPolicyEngine{
		policySet: cedar.NewPolicySet(),
	}
	for _, opt := range opts {
		err := opt(engine)
		if err != nil {
			return nil, err
		}
	}

	return engine, nil
}

// WithPath specifies the path to load policies from.
func WithPath(policyPath string) Option {
	return func(engine *cedarPolicyEngine) error {
		glob := filepath.Join(policyPath, "*.cedar")

		files, err := filepath.Glob(glob)
		if err != nil {
			return fmt.Errorf("failed to glob *.cedar policy files: %w", err)
		}

		for _, policyFile := range files {
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
				engine.policySet.Add(cedar.PolicyID(id), policy)
			}
		}

		return nil
	}
}

// WithFile specifies the file to load policies from.
func WithFile(policyFile string) Option {
	return func(engine *cedarPolicyEngine) error {
		policyBytes, err := os.ReadFile(policyFile)
		if err != nil {
			return fmt.Errorf("failed to read policy file: %w", err)
		}

		return WithBytes(policyFile, policyBytes)(engine)
	}
}

// WithBytes specifies the bytes to load policies from.
func WithBytes(name string, policyBytes []byte) Option {
	return func(engine *cedarPolicyEngine) error {
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
