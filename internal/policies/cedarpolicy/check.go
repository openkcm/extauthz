package cedarpolicy

import (
	"encoding/json"
	"errors"

	"github.com/cedar-policy/cedar-go"

	"github.com/openkcm/extauthz/internal/policies"
)

var (
	ErrUnexpectedPolicyEngine = errors.New("unexpected policy engine type")
)

func WithSubject(subject string) policies.CheckOption {
	return func(d policies.Engine) error {
		cpe, ok := d.(*cedarPolicyEngine)
		if !ok {
			return ErrUnexpectedPolicyEngine
		}

		cpe.request.Principal = cedar.NewEntityUID("Subject", cedar.String(subject))

		return nil
	}
}

func WithAction(action string) policies.CheckOption {
	return func(d policies.Engine) error {
		cpe, ok := d.(*cedarPolicyEngine)
		if !ok {
			return ErrUnexpectedPolicyEngine
		}

		cpe.request.Action = cedar.NewEntityUID("Action", cedar.String(action))

		return nil
	}
}
func WithRoute(route string) policies.CheckOption {
	return func(d policies.Engine) error {
		cpe, ok := d.(*cedarPolicyEngine)
		if !ok {
			return ErrUnexpectedPolicyEngine
		}

		cpe.request.Resource = cedar.NewEntityUID("Route", cedar.String(route))

		return nil
	}
}

func WithContextData(data map[string]string) policies.CheckOption {
	return func(d policies.Engine) error {
		cpe, ok := d.(*cedarPolicyEngine)
		if !ok {
			return ErrUnexpectedPolicyEngine
		}

		cedarContext := cedar.RecordMap{}
		for k, v := range data {
			cedarContext[cedar.String(k)] = cedar.String(v)
		}

		cpe.request.Context = cedar.NewRecord(cedarContext)

		return nil
	}
}

func (e *cedarPolicyEngine) Check(opts ...policies.CheckOption) (bool, string, error) {
	cpe := &cedarPolicyEngine{
		request: cedar.Request{},
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		err := opt(cpe)
		if err != nil {
			return false, "", err
		}
	}

	// call the cedar engine
	decision, diagnostic := cedar.Authorize(e.policySet, nil, cpe.request)

	// marshal the diagnostic
	diagnosticBytes, err := json.Marshal(diagnostic)
	if err != nil {
		return false, "", err
	}

	// return the decision
	return bool(decision), string(diagnosticBytes), nil
}
