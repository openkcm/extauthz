package flags

const (
	// DisableJWTTokenComputation disabling the existing JWT Handler, allowing the call to move forward
	DisableJWTTokenComputation = "DisableJWTTokenComputation"
	// DisableClientCertificateComputation disabling the existing client certificates handler, allowing the call to move forward
	DisableClientCertificateComputation = "DisableClientCertificateComputation"
	// EnrichHeaderWithClientRegion if set on true is including the client region. information in the headers
	EnrichHeaderWithClientRegion = "EnrichHeaderWithClientRegion"
	// EnrichHeaderWithClientType if set on true is including the client type. information in the headers
	EnrichHeaderWithClientType = "EnrichHeaderWithClientType"
)
