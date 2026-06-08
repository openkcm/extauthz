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

// request represents an authorization request being constructed.
// It implements the Engine interface but panics on Check() since
// it's only meant to be configured, not executed.
type request struct {
	principal cedar.EntityUID
	action    cedar.EntityUID
	resource  cedar.EntityUID
	context   cedar.Record
}

// Check implements Engine interface but panics - request is not an engine.
func (r *request) Check(opts ...policies.CheckOption) (bool, string, error) {
	panic("request.Check should never be called - request is for building, not executing")
}

func WithSubject(subject string) policies.CheckOption {
	return func(d policies.Engine) error {
		req, ok := d.(*request)
		if !ok {
			return ErrUnexpectedPolicyEngine
		}

		req.principal = cedar.NewEntityUID("Subject", cedar.String(subject))

		return nil
	}
}

func WithAction(action string) policies.CheckOption {
	return func(d policies.Engine) error {
		req, ok := d.(*request)
		if !ok {
			return ErrUnexpectedPolicyEngine
		}

		req.action = cedar.NewEntityUID("Action", cedar.String(action))

		return nil
	}
}

func WithContextData(data map[string]string) policies.CheckOption {
	return func(d policies.Engine) error {
		req, ok := d.(*request)
		if !ok {
			return ErrUnexpectedPolicyEngine
		}

		cedarContext := cedar.RecordMap{}
		for k, v := range data {
			cedarContext[cedar.String(k)] = cedar.String(v)
		}

		req.context = cedar.NewRecord(cedarContext)

		return nil
	}
}

func (e *cedarPolicyEngine) Check(opts ...policies.CheckOption) (bool, string, error) {
	req := &request{}

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		err := opt(req)
		if err != nil {
			return false, "", err
		}
	}

	cedarReq := cedar.Request{
		Principal: req.principal,
		Action:    req.action,
		Resource:  req.resource,
		Context:   req.context,
	}

	// call the cedar engine
	decision, diagnostic := cedar.Authorize(e.policySet, nil, cedarReq)

	// marshal the diagnostic
	diagnosticBytes, err := json.Marshal(diagnostic)
	if err != nil {
		return false, "", err
	}

	// return the decision
	return bool(decision), string(diagnosticBytes), nil
}
