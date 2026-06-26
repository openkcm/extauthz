package extauthz

import (
	"github.com/openkcm/extauthz/internal/clientdata"
)

type checkResultCode uint

const (
	UNKNOWN checkResultCode = iota
	ALLOWED
	TENANT_BLOCKED
	DENIED
	UNAUTHENTICATED
)

func (c checkResultCode) String() string {
	switch c {
	case ALLOWED:
		return "ALLOWED"
	case TENANT_BLOCKED:
		return "TENANT_BLOCKED"
	case DENIED:
		return "DENIED"
	case UNAUTHENTICATED:
		return "UNAUTHENTICATED"
	default:
		return "UNKNOWN"
	}
}

// authKind identifies which credential channel produced a checkResult.
// It is set by each credential branch in Check() before merging so the
// surviving result carries provenance for the ext_authz.auth_type span
// attribute.
type authKind uint

const (
	authKindNone authKind = iota
	authKindX509
	authKindJWT
	authKindSession
)

// Auth type span attribute values.
const (
	authTypeNone       = "none"
	authTypeX509Label  = "x509"
	authTypeJWTLabel   = "jwt"
	authTypeSessionStr = "session"
)

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

	// kind records which credential channel produced this result. It rides
	// the same merge precedence as `is`: when a more-restrictive result wins,
	// its kind is adopted as well.
	kind authKind
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

// merge updates the result if the other result is more restrictive.
// The merge adopts the more-restrictive result's `kind` along with its
// other fields so the surviving auth_type label reflects which credential
// channel produced the decision.
func (cr *checkResult) merge(other checkResult) {
	// UNKNOWN < ALLOWED < TENANT_BLOCKED < DENIED < UNAUTHENTICATED
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
		cr.kind = other.kind
	}
}

// authType returns the lower-case label corresponding to the credential
// channel that produced this result.
func (r *checkResult) authType() string {
	switch r.kind {
	case authKindX509:
		return authTypeX509Label
	case authKindJWT:
		return authTypeJWTLabel
	case authKindSession:
		return authTypeSessionStr
	default:
		return authTypeNone
	}
}
