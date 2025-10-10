package extauthz

import (
	"github.com/openkcm/extauthz/internal/clientdata"
)

type checkResultCode uint

const (
	UNKNOWN checkResultCode = iota
	ALWAYS_ALLOW
	ALLOWED
	DENIED
	UNAUTHENTICATED
)

type checkResult struct {
	is      checkResultCode
	info    string
	subject string
	email   string
	region  string
	issuer  string
	groups  []string

	withXFCCHeader bool
}

func (r *checkResult) toClientDataOptions() []clientdata.Option {
	clientType := clientdata.User

	switch {
	case r.withXFCCHeader && r.email != "":
		clientType = clientdata.TechnicalUser
	case r.withXFCCHeader && r.email == "":
		clientType = clientdata.System
	}

	return []clientdata.Option{
		clientdata.WithSubject(r.subject),
		clientdata.WithClientType(clientType),
		clientdata.WithEmail(r.email),
		clientdata.WithRegion(r.region),
		clientdata.WithGroups(r.groups),
		clientdata.WithIssuer(r.issuer),
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
		cr.issuer = other.issuer
	}
}
