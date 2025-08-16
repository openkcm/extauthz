package extauthz

import (
	"github.com/openkcm/extauthz/internal/clientdata"
)

type checkResultCode uint

const (
	UNKNOWN checkResultCode = iota
	ALLOWED
	DENIED
	UNAUTHENTICATED

	ALWAYS_ALLOW = 100
)

type checkResult struct {
	is      checkResultCode
	info    string
	subject string
	email   string
	region  string
	groups  []string
}

func (r *checkResult) toClientDataOption(withXFCCHeader bool) []clientdata.Option {
	clientType := clientdata.User

	switch {
	case withXFCCHeader && r.email != "":
		clientType = clientdata.TechnicalUser
	case withXFCCHeader && r.email == "":
		clientType = clientdata.System
	}

	return []clientdata.Option{
		clientdata.WithSubject(r.subject),
		clientdata.WithClientType(clientType),
		clientdata.WithEmail(r.email),
		clientdata.WithRegion(r.region),
		clientdata.WithGroups(r.groups),
	}
}

// merge updates the result if the other result is more restrictive
func (cr *checkResult) merge(other checkResult) {
	// UNKNOWN < ALLOWED < DENIED < UNAUTHENTICATED
	if other.is > cr.is {
		cr.is = other.is
		cr.info = other.info
		cr.subject = other.subject
		cr.email = other.email
		cr.region = other.region
		cr.groups = other.groups
	}
}
