package extauthz

import (
	"github.com/openkcm/extauthz/internal/clientdata"
)

type checkResultCode uint

const (
	UNKNOWN checkResultCode = iota
	ALWAYS_ALLOWED
	ALLOWED
	DENIED
	UNAUTHENTICATED
)

func (c checkResultCode) String() string {
	switch c {
	case ALWAYS_ALLOWED:
		return "always allowed"
	case ALLOWED:
		return "allowed"
	case DENIED:
		return "denied"
	case UNAUTHENTICATED:
		return "unauthenticated"
	default:
		return "unknown"
	}
}

type checkResult struct {
	is         checkResultCode
	info       string
	subject    string
	givenname  string
	familyname string
	email      string
	region     string
	groups     []string

	authContext map[string]string

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
		// Mandatory user attributes
		clientdata.WithIdentifier(r.subject),
		clientdata.WithEmail(r.email),
		clientdata.WithGivenName(r.givenname),
		clientdata.WithFamilyName(r.familyname),
		clientdata.WithGroups(r.groups),
		// Optional user attributes
		clientdata.WithClientType(clientType),
		clientdata.WithRegion(r.region),
		// Authentication context
		clientdata.WithAuthContext(r.authContext),
	}
}

// merge updates the result if the other result is more restrictive
func (cr *checkResult) merge(other checkResult) {
	// UNKNOWN < ALLOWED < DENIED < UNAUTHENTICATED
	if other.is > cr.is {
		cr.is = other.is
		cr.info = other.info
		cr.subject = other.subject
		cr.givenname = other.givenname
		cr.familyname = other.familyname
		cr.email = other.email
		cr.region = other.region
		cr.groups = other.groups
		cr.authContext = other.authContext
	}
}
