package flags

const (
	// DisableJWTTokenComputation disabling the existing JWT Handler, allowing the call to move forward
	DisableJWTTokenComputation = "disable-jwt-token-computation"
	// DisableClientCertificateComputation disabling the existing client certificates handler, allowing the call to move forward
	DisableClientCertificateComputation = "disable-client-certificate-computation"
	// EnrichHeaderWithClientRegion if set on true is including the client region. information in the headers
	EnrichHeaderWithClientRegion = "enrich-header-with-client-region"
	// EnrichHeaderWithClientType if set on true is including the client type. information in the headers
	EnrichHeaderWithClientType = "enrich-header-with-client-type"
)
