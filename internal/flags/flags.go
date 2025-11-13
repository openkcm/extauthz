package flags

const (
	// DisableJWTTokenComputation disabling the existing JWT Handler, allowing the call to move forward
	DisableJWTTokenComputation = "disable-jwt-token-computation"
	// DisableJWTTokenIntrospection disabling the JWT Introspection, allowing the call to move forward
	DisableJWTTokenIntrospection = "disable-jwt-token-introspection"
	// DisableClientCertificateComputation disabling the existing client certificates handler, allowing the call to move forward
	DisableClientCertificateComputation = "disable-client-certificate-computation"
	// EnableHttpIssuerScheme allows issuers with "http" scheme (not secure) to be accepted
	EnableHttpIssuerScheme = "enable-http-issuer-scheme"
)
