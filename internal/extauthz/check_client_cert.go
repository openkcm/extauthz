package extauthz

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/go-andiamo/splitter"
)

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
func (srv *Server) checkClientCert(_ context.Context, certHeader, method, host, path string) checkResult {
	// create map of fields
	fields, err := mapHeader(certHeader)
	if err != nil {
		return checkResult{is: UNAUTHENTICATED,
			info: "Invalid certificate header"}
	}

	// extract the subject from the cert header
	subject, ok := fields["Subject"]
	if !ok {
		return checkResult{is: UNAUTHENTICATED,
			info: "Missing subject in client certificate"}
	}

	// check if the subject is trusted and extract the region
	region, ok := srv.trustedSubjectToRegion[subject]
	if !ok {
		return checkResult{is: DENIED,
			info: "Subject not trusted"}
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
	slog.Debug("Checking policies for x509",
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
