package extauthz

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-andiamo/splitter"

	slogctx "github.com/veqryn/slog-context"
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

// formatSubjectLikeEnvoyXFCC returns the subject in the same format used by Envoy's XFCC header
func formatSubjectLikeEnvoyXFCC(subject pkix.Name) string {
	parts := make([]string, 0)

	// 1. CN
	if subject.CommonName != "" {
		parts = append(parts, "CN="+subject.CommonName)
	}

	// 2. L
	for _, l := range subject.Locality {
		parts = append(parts, "L="+l)
	}

	// 3. OU (in reverse order — like in Envoy’s output)
	for i := len(subject.OrganizationalUnit) - 1; i >= 0; i-- {
		parts = append(parts, "OU="+subject.OrganizationalUnit[i])
	}

	// 4. O
	for _, o := range subject.Organization {
		parts = append(parts, "O="+o)
	}

	// 5. C
	for _, c := range subject.Country {
		parts = append(parts, "C="+c)
	}

	return strings.Join(parts, ",")
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
	crtSubject := formatSubjectLikeEnvoyXFCC(crt.Subject)

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

	// check if the subject is trusted and extract the region
	region, ok := srv.trustedSubjectToRegion[subject]
	if !ok {
		return checkResult{is: DENIED,
			info: "Subject not trusted"}
	}

	// check time bounds
	if crt.NotBefore.After(time.Now()) {
		return checkResult{is: DENIED,
			info: "Certificate not yet valid"}
	}

	if crt.NotAfter.Before(time.Now()) {
		return checkResult{is: DENIED,
			info: "Certificate expired"}
	}

	// check the policies
	slogctx.Debug(ctx, "Checking policies for x509",
		"subject", subject,
		"issuer", crt.Issuer.String(),
		"method", method,
		"host", host,
		"path", path)

	allowed, reason, err := srv.policyEngine.Check(subject, method, host+path,
		map[string]string{
			"type":   "x509",
			"issuer": crt.Issuer.String(),
		})
	if err != nil {
		return checkResult{is: UNAUTHENTICATED,
			info: fmt.Sprintf("Error from policy engine: %v", err)}
	}

	if !allowed {
		return checkResult{is: DENIED,
			info: fmt.Sprintf("Reason from policy engine: %v", reason)}
	}

	// extract the email address from the certificate
	email := ""
	if len(crt.EmailAddresses) > 0 {
		email = crt.EmailAddresses[0]
	}

	return checkResult{
		is:      ALLOWED,
		subject: subject,
		region:  region,
		email:   email,
	}
}
