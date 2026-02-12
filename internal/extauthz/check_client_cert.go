package extauthz

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-andiamo/splitter"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
)

var (
	ReExSubject        = regexp.MustCompile(`Subject="([^"]+)"`)
	ErrSubjectNotFound = errors.New("subject not found")
)

func extractSubject(header string) (string, error) {
	matches := ReExSubject.FindStringSubmatch(header)
	if len(matches) < 2 {
		return "", ErrSubjectNotFound
	}

	return matches[1], nil
}

// oidShortNames maps ASN.1 OID strings to their RFC 2253 short names.
// This is used to represent DN attribute types in a human-readable form.
var oidShortNames = map[string]string{
	"2.5.4.3":                    "CN",     // commonName
	"2.5.4.7":                    "L",      // localityName
	"2.5.4.8":                    "ST",     // stateOrProvinceName
	"2.5.4.10":                   "O",      // organizationName
	"2.5.4.11":                   "OU",     // organizationalUnitName
	"2.5.4.6":                    "C",      // countryName
	"2.5.4.9":                    "STREET", // streetAddress
	"0.9.2342.19200300.100.1.25": "DC",     // domainComponent
	"0.9.2342.19200300.100.1.1":  "UID",    // userID
}

// escapeRFC2253 escapes special characters in a DN attribute value
// according to RFC 2253 rules. This includes characters like commas,
// plus signs, quotes, backslashes, and more. Leading/trailing spaces
// and leading '#' are also escaped.
//
// val: the string value to escape
// Returns the escaped string safe for inclusion in an RFC 2253 DN
func escapeRFC2253(val string) string {
	var b strings.Builder

	for i, r := range val {
		if r == ',' || r == '+' || r == '"' || r == '\\' || r == '<' || r == '>' || r == ';' || r == '=' {
			b.WriteRune('\\')
		}
		// Escape leading or trailing spaces or leading '#'
		if (i == 0 && (r == ' ' || r == '#')) || (i == len(val)-1 && r == ' ') {
			b.WriteRune('\\')
		}

		b.WriteRune(r)
	}

	return b.String()
}

// formatRDNSequence takes a pkix.RDNSequence (ASN.1 parsed DN)
// and formats it into a string following RFC 2253 rules, matching Envoy's format.
//
// - RDNs are printed in reverse order (most specific first).
// - Multiple attributes in a single RDN are joined with '+'.
// - Attribute types use short names when known (e.g. CN, OU).
// - Attribute values are escaped properly.
//
// rdns: the RDNSequence to format
// Returns the formatted DN string.
func formatRDNSequence(rdns pkix.RDNSequence) string {
	var parts []string
	// Reverse the RDN order
	for i := len(rdns) - 1; i >= 0; i-- {
		var attrs []string

		for _, atv := range rdns[i] {
			name := oidShortNames[atv.Type.String()]
			if name == "" {
				name = atv.Type.String()
			}

			val := fmt.Sprintf("%v", atv.Value)
			attrs = append(attrs, fmt.Sprintf("%s=%s", name, escapeRFC2253(val)))
		}

		parts = append(parts, strings.Join(attrs, "+"))
	}

	return strings.Join(parts, ",")
}

// formatSubject extracts the ASN.1 raw subject field from a certificate,
// parses it into an RDNSequence, and returns the RFC 2253 formatted string.
//
// cert: the X.509 certificate to extract subject from
// Returns the formatted subject string or an empty string on parse failure.
func formatSubject(cert *x509.Certificate) string {
	var rdnSeq pkix.RDNSequence

	_, err := asn1.Unmarshal(cert.RawSubject, &rdnSeq)
	if err != nil {
		return ""
	}

	return formatRDNSequence(rdnSeq)
}

// formatIssuer extracts the ASN.1 raw issuer field from a certificate,
// parses it into an RDNSequence, and returns the RFC 2253 formatted string.
//
// cert: the X.509 certificate to extract issuer from
// Returns the formatted issuer string or an empty string on parse failure.
func formatIssuer(cert *x509.Certificate) string {
	var rdnSeq pkix.RDNSequence

	_, err := asn1.Unmarshal(cert.RawIssuer, &rdnSeq)
	if err != nil {
		return ""
	}

	return formatRDNSequence(rdnSeq)
}

// mapHeader takes a string "FOO=bar;BAZ=qux" and returns a map[string]string{"FOO": "bar", "BAZ": "qux"}
func mapHeader(header string) (map[string]string, error) {
	// split on ; preserving quoted values
	spl, err := splitter.NewSplitter(';', splitter.DoubleQuotes)
	if err != nil {
		return nil, err
	}

	fields, err := spl.Split(header)
	if err != nil {
		return nil, err
	}
	// split on = and trim quotes
	m := make(map[string]string, len(fields))
	for _, field := range fields {
		if k, v, ok := strings.Cut(field, "="); ok {
			m[k] = strings.Trim(v, `"`)
		} else {
			return nil, fmt.Errorf("invalid field: %s", field)
		}
	}

	return m, nil
}

// parseCert takes a URL-encoded PEM certificate and returns the parsed x509.Certificate.
func parseCert(urlEncodedPem string) (*x509.Certificate, error) {
	pemData, err := url.QueryUnescape(urlEncodedPem)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing certificate: block is nil")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate: block type is %s", block.Type)
	}

	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return crt, nil
}

// checkClientCert checks the request using the subject from the client certificate.
func (srv *Server) checkClientCert(ctx context.Context, certHeader, method, host, path string) checkResult {
	// create map of fields
	fields, err := mapHeader(certHeader)
	if err != nil {
		return checkResult{is: UNAUTHENTICATED,
			info: "Invalid certificate header"}
	}

	// decode and parse the x509 certificate and
	urlEncodedPem, ok := fields["Cert"]
	if !ok {
		return checkResult{is: UNAUTHENTICATED,
			info: "Missing certificate in XFCC header"}
	}

	crt, err := parseCert(urlEncodedPem)
	if err != nil {
		return checkResult{is: UNAUTHENTICATED,
			info: "Failed to parse x509 certificate"}
	}

	// format the certificate subject as per envoy structure
	crtSubject := formatSubject(crt)

	// extract the subject from the cert header
	subject, err := extractSubject(certHeader)
	if err != nil {
		subject = crtSubject
	}

	if subject != crtSubject {
		slogctx.Debug(ctx, "Certificate and header Subject do not match",
			"certSubject", crtSubject,
			"subject", subject)

		return checkResult{is: DENIED,
			info: "Header subject not matching with certificate subject"}
	}

	// prepare the result
	res := checkResult{
		is:      UNKNOWN,
		subject: subject,
	}

	// check if the subject is trusted and extract the region
	region, ok := srv.trustedSubjectToRegion[subject]
	if !ok {
		res.is = DENIED
		res.info = "Subject not trusted"
		return res
	}
	res.region = region

	// check time bounds
	if crt.NotBefore.After(time.Now()) {
		res.is = DENIED
		res.info = "Certificate not yet valid"
		return res
	}

	if crt.NotAfter.Before(time.Now()) {
		res.is = DENIED
		res.info = "Certificate expired"
		return res
	}

	crtIssuer := formatIssuer(crt)
	// check the policies
	slogctx.Debug(ctx, "Checking policies for x509",
		"subject", subject,
		"issuer", crtIssuer,
		"method", method,
		"host", host,
		"path", path)

	data := map[string]string{
		"host":   host,
		"path":   path,
		"type":   "x509",
		"issuer": crtIssuer,
	}

	allowed, reason, err := srv.policyEngine.Check(
		cedarpolicy.WithSubject(subject),
		cedarpolicy.WithAction(method),
		cedarpolicy.WithContextData(data),
	)
	if err != nil {
		res.is = UNAUTHENTICATED
		res.info = fmt.Sprintf("Error from policy engine: %v", err)
		return res
	}

	if !allowed {
		res.is = DENIED
		res.info = fmt.Sprintf("Reason from policy engine: %v", reason)
		return res
	}

	// extract the email address from the certificate
	email := ""
	if len(crt.EmailAddresses) > 0 {
		email = crt.EmailAddresses[0]
	}
	res.email = email

	res.is = ALLOWED
	return res
}
