package policy

import (
	"encoding/json"

	cedar "github.com/cedar-policy/cedar-go"
)

// Check checks if the subject has the permission to perform the action on the route.
func (e *cedarEngine) Check(subject, action, route string, cntxt map[string]string) (bool, string, error) {
	// prepare the context
	cedarContext := cedar.RecordMap{}
	for k, v := range cntxt {
		cedarContext[cedar.String(k)] = cedar.String(v)
	}
	// we additionally need the route in the context to be able to use wildcard checks
	cedarContext["route"] = cedar.String(route)

	// prepare the request
	request := cedar.Request{
		Principal: cedar.NewEntityUID("Subject", cedar.String(subject)),
		Action:    cedar.NewEntityUID("Action", cedar.String(action)),
		Resource:  cedar.NewEntityUID("Route", cedar.String(route)),
		Context:   cedar.NewRecord(cedarContext),
	}

	// call the cedar engine
	decision, diagnostic := cedar.Authorize(e.policySet, nil, request)

	// marshal the diagnostic
	diagnosticBytes, err := json.Marshal(diagnostic)
	if err != nil {
		return false, "", err
	}

	// return the decision
	return bool(decision), string(diagnosticBytes), nil
}
