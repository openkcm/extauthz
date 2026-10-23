//go:build helmtests

package main_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"maps"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openkcm/common-sdk/pkg/auth"
	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	envoyauth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/openkcm/extauthz/internal/business"
	"github.com/openkcm/extauthz/internal/clientdata"
	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
)

// The tests in this file prove the documentation of the files that the ExtAuthZ
// configuration reads. testdata/files holds the example contents that values.yaml shows;
// TestFileExamplesInValues checks that values.yaml shows exactly these files, and the other
// tests read them with ExtAuthZ's own code. Keys and certificates are generated at test
// time.

const (
	filesDir         = "testdata/files"
	exampleCA        = "CN=Example Client CA,O=Example Corp,C=DE"
	billingEU10      = "CN=billing,OU=Clients,O=Example Corp,C=DE"
	reportingEU10    = "CN=reporting,OU=Clients,O=Example Corp,C=DE"
	billingUS10      = `CN=billing,OU=Clients,O=Example\, Inc.,C=US`
	activeKeyID      = "key-2026-10"
	automationIssuer = "https://idp.example.com/realms/automation"
)

// TestFileExamplesInValues checks that each example file content in values.yaml, the
// commented block after the line with the marker, is the file in testdata/files.
func TestFileExamplesInValues(t *testing.T) {
	valuesYAML, err := os.ReadFile(filepath.Join(path, "values.yaml"))
	if err != nil {
		t.Fatalf("reading values.yaml: %v", err)
	}
	lines := strings.Split(string(valuesYAML), "\n")

	examples := []struct{ file, marker string }{
		{"trustedSubjects.yaml", "Example content of trustedSubjects.yaml:"},
		{"systems.cedar", "Example content of systems.cedar:"},
		{"users.cedar", "Example content of users.cedar:"},
		{"keyId", "Example content of keyId:"},
		{"valkey.json", "Example content of valkey.json:"},
	}
	for _, ex := range examples {
		t.Run(ex.file, func(t *testing.T) {
			got := exampleInValues(t, lines, ex.marker)
			want := string(readTestdata(t, ex.file))
			if got != want {
				t.Errorf("the example in values.yaml differs from %s/%s\n"+
					"values.yaml:\n%s\ntestdata:\n%s", filesDir, ex.file, got, want)
			}
		})
	}
}

// exampleInValues returns the commented block after the only line of values.yaml that
// contains marker: the following comment lines whose text is indented by two spaces, without
// the comment prefix and these two spaces.
func exampleInValues(t *testing.T, lines []string, marker string) string {
	t.Helper()
	found := -1
	for i, line := range lines {
		if strings.Contains(line, marker) {
			if found >= 0 {
				t.Fatalf("values.yaml contains %q more than once", marker)
			}
			found = i
		}
	}
	if found < 0 {
		t.Fatalf("values.yaml does not contain %q", marker)
	}

	prefix := lines[found][:strings.Index(lines[found], "#")] + "#   "
	var b strings.Builder
	for _, line := range lines[found+1:] {
		text, ok := strings.CutPrefix(line, prefix)
		if !ok {
			break
		}
		b.WriteString(text + "\n")
	}

	return b.String()
}

// TestMountedFilesWithExtAuthZ starts ExtAuthZ as cmd/extauthz does, with the chart's
// configuration and with the example trusted subjects and policies and a signing key
// generated here, laid out like the chart's default volumes. It then asks ExtAuthZ, as Envoy
// does, about requests with client certificates generated here, and verifies the signed
// client data as CMK does.
func TestMountedFilesWithExtAuthZ(t *testing.T) {
	root := t.TempDir()
	mtlsDir := filepath.Join(root, "extauthz-mtls")
	policiesDir := filepath.Join(root, "extauthz-policies")
	signingDir := filepath.Join(root, "extauthz-signing")

	signingKey := newRSAKey(t)
	writeVolume(t, mtlsDir, map[string][]byte{
		"trustedSubjects.yaml": readTestdata(t, "trustedSubjects.yaml"),
	})
	writeVolume(t, policiesDir, map[string][]byte{
		"systems.cedar": readTestdata(t, "systems.cedar"),
		"users.cedar":   readTestdata(t, "users.cedar"),
	})
	writeVolume(t, signingDir, map[string][]byte{
		"keyId":                  readTestdata(t, "keyId"),
		activeKeyID + ".pem":     pkcs8PEM(t, signingKey),
		"key-2026-04.pem":        pkcs1PEM(t, newRSAKey(t)),
		"unrelated-file-ignored": []byte("not a key"),
	})

	cfg := loadRenderedConfig(t,
		"config.mtls.trustedSubjectsYaml="+filepath.Join(mtlsDir, "trustedSubjects.yaml"),
		"config.cedar.policyPath="+policiesDir,
		"config.clientData.signingKeyIDFilePath="+filepath.Join(signingDir, "keyId"),
		"config.grpcServer.address="+freeAddress(t),
	)
	extauthz := startExtAuthZ(t, cfg)

	// CMK verifies the client data with the public key <key ID>.pem, in the form that
	// `openssl pkey -pubout` writes.
	cmkPublicKeys := map[string][]byte{activeKeyID: publicKeyPEM(t, &signingKey.PublicKey)}

	ca := newCA(t, pkix.Name{CommonName: "Example Client CA",
		Organization: []string{"Example Corp"}, Country: []string{"DE"}})
	otherCA := newCA(t, pkix.Name{CommonName: "Other CA",
		Organization: []string{"Example Corp"}, Country: []string{"DE"}})
	clientName := func(cn, org, country string) pkix.Name {
		return pkix.Name{CommonName: cn, OrganizationalUnit: []string{"Clients"},
			Organization: []string{org}, Country: []string{country}}
	}
	billing := ca.issue(t, clientName("billing", "Example Corp", "DE"))
	reporting := ca.issue(t, clientName("reporting", "Example Corp", "DE"), "reporting@example.com")
	billingInc := ca.issue(t, clientName("billing", "Example, Inc.", "US"))
	unknown := ca.issue(t, clientName("unknown", "Example Corp", "DE"))
	billingOtherCA := otherCA.issue(t, clientName("billing", "Example Corp", "DE"))

	const keys = "/cmk/v1/tenant-1/keys"
	allowed, denied := code.Code_OK, code.Code_PERMISSION_DENIED
	tests := []struct {
		name       string
		cert       *x509.Certificate
		subject    string // as Envoy forwards it, and as in trustedSubjects.yaml
		method     string
		path       string
		wantCode   code.Code
		wantRegion string
		wantType   string
	}{
		{
			name: "billing in eu10 may POST", cert: billing, subject: billingEU10,
			method: "POST", path: keys, wantCode: allowed, wantRegion: "eu10", wantType: "system",
		},
		{
			name: "billing in eu10 may not DELETE", cert: billing, subject: billingEU10,
			method: "DELETE", path: keys + "/k1", wantCode: denied,
		},
		{
			name: "billing in eu10 only below /cmk/v1/", cert: billing, subject: billingEU10,
			method: "GET", path: "/other/v1/keys", wantCode: denied,
		},
		{
			name: "reporting, with an e-mail address, may GET", cert: reporting,
			subject: reportingEU10, method: "GET", path: keys + "?limit=10", wantCode: allowed,
			wantRegion: "eu10", wantType: "technical-user",
		},
		{
			name: "reporting may not POST", cert: reporting, subject: reportingEU10,
			method: "POST", path: keys, wantCode: denied,
		},
		{
			name: "billing in us10, subject with an escaped comma", cert: billingInc,
			subject: billingUS10, method: "GET", path: "/cmk/v1/tenant-2/keys", wantCode: allowed,
			wantRegion: "us10", wantType: "system",
		},
		{
			name: "subject not in trustedSubjects.yaml", cert: unknown,
			subject: "CN=unknown,OU=Clients,O=Example Corp,C=DE", method: "GET", path: keys,
			wantCode: denied,
		},
		{
			name: "trusted subject, certificate of another CA", cert: billingOtherCA,
			subject: billingEU10, method: "GET", path: keys, wantCode: denied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := checkWithClientCertificate(t, extauthz, tt.cert, tt.subject, tt.method, tt.path)
			if got := code.Code(resp.GetStatus().GetCode()); got != tt.wantCode {
				t.Fatalf("got %v, want %v; response: %v", got, tt.wantCode, resp)
			}
			if tt.wantCode != code.Code_OK {
				return
			}

			headers := map[string]string{}
			for _, h := range resp.GetOkResponse().GetHeaders() {
				headers[h.GetHeader().GetKey()] = h.GetHeader().GetValue()
			}
			clientData, err := auth.DecodeFrom(headers[auth.HeaderClientData])
			if err != nil {
				t.Fatalf("decoding the client data: %v; headers: %v", err, headers)
			}
			if clientData.KeyID != activeKeyID || clientData.Identifier != tt.subject ||
				clientData.Region != tt.wantRegion || clientData.Type != tt.wantType {
				t.Errorf("unexpected client data: %+v", clientData)
			}
			publicKey, err := jwt.ParseRSAPublicKeyFromPEM(cmkPublicKeys[clientData.KeyID])
			if err != nil {
				t.Fatalf("no public key for key ID %q: %v", clientData.KeyID, err)
			}
			err = clientData.Verify(*publicKey, headers[auth.HeaderClientDataSignature])
			if err != nil {
				t.Errorf("the signature does not verify with the public key: %v", err)
			}
		})
	}
}

// TestTrustedSubjectsFileErrors checks that ExtAuthZ does not start without a valid trusted
// subjects file.
func TestTrustedSubjectsFileErrors(t *testing.T) {
	root := t.TempDir()
	policiesDir := filepath.Join(root, "policies")
	signingDir := filepath.Join(root, "signing")
	writeVolume(t, policiesDir, map[string][]byte{"users.cedar": readTestdata(t, "users.cedar")})
	writeVolume(t, signingDir, map[string][]byte{"keyId": readTestdata(t, "keyId")})

	tests := []struct {
		name    string
		content string // empty: the file does not exist
	}{
		{name: "missing file"},
		{name: "list instead of region map", content: "- " + billingEU10 + "\n"},
		{name: "empty subject", content: "eu10:\n  - \"\"\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "trustedSubjects.yaml")
			if tt.content != "" {
				writeFile(t, file, []byte(tt.content))
			}
			cfg := &config.Config{}
			cfg.MTLS.TrustedSubjectsYaml = file
			cfg.Cedar.PolicyPath = policiesDir
			cfg.ClientData.SigningKeyIDFilePath = filepath.Join(signingDir, "keyId")

			// If ExtAuthZ started anyway, it would serve until the context ends.
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			err := business.Main(ctx, cfg)
			if err == nil || !strings.Contains(err.Error(), "failed to load trusted subjects") {
				t.Fatalf("expected the startup to fail on the trusted subjects, got %v", err)
			}
		})
	}
}

// TestCedarPolicyFiles loads the example policy files the way ExtAuthZ loads
// config.cedar.policyPath and evaluates requests of every type with the documented request
// model.
func TestCedarPolicyFiles(t *testing.T) {
	permitAll := []byte("permit (principal, action, resource);\n")
	dir := t.TempDir()
	writeVolume(t, dir, map[string][]byte{
		"systems.cedar": readTestdata(t, "systems.cedar"),
		"users.cedar":   readTestdata(t, "users.cedar"),
		// Not loaded: the name does not end in .cedar.
		"README.md": permitAll,
	})
	// Not loaded: in a subdirectory.
	writeFile(t, filepath.Join(dir, "more", "all.cedar"), permitAll)

	engine, err := cedarpolicy.NewEngine(cedarpolicy.WithPath(dir))
	if err != nil {
		t.Fatalf("loading the policies: %v", err)
	}

	certContext := func(issuer string) map[string]string {
		return map[string]string{"host": "cmk.example.com", "type": "x509", "issuer": issuer}
	}
	jwtContext := map[string]string{"host": "cmk.example.com", "type": "jwt",
		"issuer": automationIssuer, "jwksURI": ""}
	sessionContext := map[string]string{"host": "cmk.example.com", "type": "session",
		"issuer": "https://tenant-1.idp.example.com"}

	tests := []struct {
		name      string
		principal string
		action    string
		path      string
		context   map[string]string
		want      bool
	}{
		{"certificate subject", billingEU10, "POST", "/cmk/v1/tenant-1/keys",
			certContext(exampleCA), true},
		{"certificate subject with an escaped comma", billingUS10, "GET", "/cmk/v1/t/keys",
			certContext(exampleCA), true},
		{"certificate subject, action not permitted", billingUS10, "POST", "/cmk/v1/t/keys",
			certContext(exampleCA), false},
		{"certificate of another issuer", billingEU10, "GET", "/cmk/v1/t/keys",
			certContext("CN=Other CA,O=Example Corp,C=DE"), false},
		{"technical user with a token", "automation-client", "DELETE", "/cmk/v1/t/keys/k1",
			jwtContext, true},
		{"other token subject", "someone-else", "GET", "/cmk/v1/t/keys", jwtContext, false},
		{"user with a session", "user-1", "PATCH", "/cmk/v1/tenant-1/keys/k1", sessionContext,
			true},
		{"user with a session, path with a query string", "user-1", "GET",
			"/cmk/v1/tenant-1/keys?limit=10", sessionContext, true},
		{"user with a session, other path", "user-1", "GET", "/cmk/v2/tenant-1/keys",
			sessionContext, false},
		{"certificate subject with a token", billingEU10, "GET", "/cmk/v1/t/keys", jwtContext,
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := map[string]string{"path": tt.path}
			maps.Copy(data, tt.context)
			allowed, diagnostic, err := engine.Check(
				cedarpolicy.WithSubject(tt.principal),
				cedarpolicy.WithAction(tt.action),
				cedarpolicy.WithContextData(data),
			)
			if err != nil {
				t.Fatalf("evaluating: %v", err)
			}
			if allowed != tt.want {
				t.Errorf("allowed = %v, want %v; diagnostic: %s", allowed, tt.want, diagnostic)
			}
		})
	}

	t.Run("a policy that does not parse stops the startup", func(t *testing.T) {
		broken := t.TempDir()
		writeFile(t, filepath.Join(broken, "broken.cedar"), []byte("permit (principal, action);\n"))
		_, err := cedarpolicy.NewEngine(cedarpolicy.WithPath(broken))
		if err == nil {
			t.Fatal("expected an error")
		}
	})
}

// TestSigningKeyFiles signs client data with the key directory layout of
// config.clientData.signingKeyIDFilePath, as ExtAuthZ does, and verifies it as CMK does.
func TestSigningKeyFiles(t *testing.T) {
	current := newRSAKey(t)
	previous := newRSAKey(t)
	keys := map[string][]byte{
		activeKeyID + ".pem": pkcs8PEM(t, current),  // PKCS #8: BEGIN PRIVATE KEY
		"key-2026-04.pem":    pkcs1PEM(t, previous), // PKCS #1: BEGIN RSA PRIVATE KEY
	}

	tests := []struct {
		name    string
		keyID   []byte
		wantKID string
		wantKey *rsa.PrivateKey
	}{
		{name: "keyId of testdata, with a trailing newline; key in PKCS #8",
			keyID: readTestdata(t, "keyId"), wantKID: activeKeyID, wantKey: current},
		{name: "key in PKCS #1", keyID: []byte("key-2026-04"), wantKID: "key-2026-04",
			wantKey: previous},
		{name: "no key file for the key ID", keyID: []byte("key-2027-01")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string][]byte{"keyId": tt.keyID}
			maps.Copy(files, keys)
			dir := t.TempDir()
			writeVolume(t, dir, files)

			signer, err := clientdata.NewSigner(&commoncfg.FeatureGates{},
				&config.ClientData{SigningKeyIDFilePath: filepath.Join(dir, "keyId")})
			if err != nil {
				t.Fatalf("creating the signer: %v", err)
			}
			err = signer.Start()
			if err != nil {
				t.Fatalf("loading the key directory: %v", err)
			}
			t.Cleanup(func() { _ = signer.Close() })

			b64data, b64sig, err := signer.Sign(clientdata.WithIdentifier(billingEU10))
			if tt.wantKey == nil {
				if err == nil {
					t.Fatal("expected an error without the key file")
				}
				return
			}
			if err != nil {
				t.Fatalf("signing: %v", err)
			}

			clientData, err := auth.DecodeFrom(b64data)
			if err != nil {
				t.Fatalf("decoding: %v", err)
			}
			if clientData.KeyID != tt.wantKID {
				t.Errorf("key ID %q, want %q", clientData.KeyID, tt.wantKID)
			}
			publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM(t, &tt.wantKey.PublicKey))
			if err != nil {
				t.Fatalf("parsing the public key: %v", err)
			}
			err = clientData.Verify(*publicKey, b64sig)
			if err != nil {
				t.Errorf("the signature does not verify with the public key: %v", err)
			}
		})
	}
}

// TestCredentialFiles reads value reference files and client certificate files with the
// common-sdk functions that ExtAuthZ uses for them.
func TestCredentialFiles(t *testing.T) {
	fileRef := func(path string, format commoncfg.FileFormat, jsonPath string) commoncfg.SourceRef {
		return commoncfg.SourceRef{Source: commoncfg.FileSourceValue,
			File: commoncfg.CredentialFile{Path: path, Format: format, JSONPath: jsonPath}}
	}

	t.Run("JSON file with jsonPath", func(t *testing.T) {
		file := filepath.Join(filesDir, "valkey.json")
		fields := map[string]string{"$.user": "extauthz", "$.password": "<password>"}
		for jsonPath, want := range fields {
			ref := fileRef(file, commoncfg.JSONFileFormat, jsonPath)
			got, err := commoncfg.LoadValueFromSourceRef(ref)
			if err != nil || string(got) != want {
				t.Errorf("%s: got %q, %v; want %q", jsonPath, got, err, want)
			}
		}
	})

	t.Run("binary file keeps a trailing newline", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "password")
		writeFile(t, file, []byte("secret\n"))
		got, err := commoncfg.LoadValueFromSourceRef(fileRef(file, commoncfg.BinaryFileFormat, ""))
		if err != nil || string(got) != "secret\n" {
			t.Errorf("got %q, %v", got, err)
		}
	})

	root := newCA(t, pkix.Name{CommonName: "Example Root CA"})
	intermediate := root.issueCA(t, pkix.Name{CommonName: "Example Intermediate CA"})
	rsaKey := newRSAKey(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}

	keyFormats := []struct {
		name   string
		key    crypto.Signer
		keyPEM []byte
	}{
		{"PKCS #8 RSA key", rsaKey, pkcs8PEM(t, rsaKey)},
		{"PKCS #1 RSA key", rsaKey, pkcs1PEM(t, rsaKey)},
		{"EC key", ecKey, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})},
	}
	for _, kf := range keyFormats {
		t.Run("client certificate with "+kf.name, func(t *testing.T) {
			client := intermediate.issueWithKey(t, pkix.Name{CommonName: "extauthz"}, kf.key)
			dir := t.TempDir()
			// tls.crt: the client certificate, then the intermediate CA. ca.crt: the root CA.
			writeFile(t, filepath.Join(dir, "tls.crt"),
				append(certificatePEM(client), certificatePEM(intermediate.cert)...))
			writeFile(t, filepath.Join(dir, "tls.key"), kf.keyPEM)
			writeFile(t, filepath.Join(dir, "ca.crt"), certificatePEM(root.cert))

			serverCA := fileRef(filepath.Join(dir, "ca.crt"), commoncfg.BinaryFileFormat, "")
			tlsConfig, err := commoncfg.LoadMTLSConfig(&commoncfg.MTLS{
				Cert:     fileRef(filepath.Join(dir, "tls.crt"), commoncfg.BinaryFileFormat, ""),
				CertKey:  fileRef(filepath.Join(dir, "tls.key"), commoncfg.BinaryFileFormat, ""),
				ServerCA: &serverCA,
			})
			if err != nil {
				t.Fatalf("loading the files: %v", err)
			}
			chain := tlsConfig.Certificates[0].Certificate
			if len(chain) != 2 {
				t.Fatalf("expected the client certificate and the intermediate CA, got %d",
					len(chain))
			}
			// The CA file was read: the chain verifies against it.
			intermediates := x509.NewCertPool()
			intermediates.AddCert(intermediate.cert)
			_, err = client.Verify(x509.VerifyOptions{
				Roots:         tlsConfig.RootCAs,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			})
			if err != nil {
				t.Errorf("the chain does not verify against ca.crt: %v", err)
			}
		})
	}
}

// loadRenderedConfig renders config.yaml with the chart's default values and the given
// --set-string values, and loads it as cmd/extauthz does.
func loadRenderedConfig(t *testing.T, setValues ...string) *config.Config {
	t.Helper()
	args := []string{"template", appName, path, "-s", "templates/configmap.yaml"}
	for _, v := range setValues {
		args = append(args, "--set-string", v)
	}
	cmd := exec.CommandContext(t.Context(), "helm", args...)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s%s", err, out.String(), stderr.String())
	}

	var configMap struct {
		Data map[string]string `yaml:"data"`
	}
	err = yaml.Unmarshal(out.Bytes(), &configMap)
	if err != nil {
		t.Fatalf("parsing the ConfigMap: %v", err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), []byte(configMap.Data["config.yaml"]))

	cfg := &config.Config{}
	err = commoncfg.LoadConfig(cfg, map[string]any{}, dir)
	if err != nil {
		t.Fatalf("loading the rendered configuration: %v", err)
	}

	return cfg
}

// startExtAuthZ runs ExtAuthZ's business logic, as cmd/extauthz does after loading the
// configuration, until the test ends, and returns a client of its ext_authz gRPC API.
func startExtAuthZ(t *testing.T, cfg *config.Config) envoyauth.AuthorizationClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	var mainErr error
	go func() {
		mainErr = business.Main(ctx, cfg)
		close(stopped)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			t.Error("ExtAuthZ did not stop")
		}
	})

	address := cfg.GRPCServer.Address
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case <-stopped:
			t.Fatalf("ExtAuthZ did not start: %v", mainErr)
		default:
		}
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", address)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ExtAuthZ does not listen on %s: %v", address, err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("creating the gRPC client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return envoyauth.NewAuthorizationClient(conn)
}

// checkWithClientCertificate sends a Check request as Envoy does for a request with a
// verified client certificate: the certificate and its subject in x-forwarded-client-cert.
func checkWithClientCertificate(t *testing.T, client envoyauth.AuthorizationClient,
	cert *x509.Certificate, subject, method, urlPath string,
) *envoyauth.CheckResponse {
	t.Helper()
	hash := sha256.Sum256(cert.Raw)
	xfcc := "Hash=" + hex.EncodeToString(hash[:]) +
		`;Cert="` + url.QueryEscape(string(certificatePEM(cert))) + `";Subject="` + subject + `"`
	req := &envoyauth.CheckRequest{Attributes: &envoyauth.AttributeContext{
		Request: &envoyauth.AttributeContext_Request{Http: &envoyauth.AttributeContext_HttpRequest{
			Method:  method,
			Host:    "cmk.example.com",
			Path:    urlPath,
			Headers: map[string]string{"x-forwarded-client-cert": xfcc},
		}},
	}}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	resp, err := client.Check(ctx, req)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	return resp
}

// writeVolume writes files into dir the way the kubelet mounts a ConfigMap or Secret: the
// files in a timestamped subdirectory, a ..data link to it, and a link for each file.
func writeVolume(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	data := "..2026_10_19_12_00_00.000000001"
	for name, content := range files {
		writeFile(t, filepath.Join(dir, data, name), content)
	}
	err := os.Symlink(data, filepath.Join(dir, "..data"))
	if err != nil {
		t.Fatal(err)
	}
	for name := range files {
		err = os.Symlink(filepath.Join("..data", name), filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
	}
}

func writeFile(t *testing.T, file string, content []byte) {
	t.Helper()
	err := os.MkdirAll(filepath.Dir(file), 0o700)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(file, content, 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(filesDir, name))
	if err != nil {
		t.Fatal(err)
	}

	return content
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()

	return address
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func pkcs8PEM(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func pkcs1PEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)

	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

func publicKeyPEM(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func certificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// testCA is a certificate authority for certificates generated at test time.
type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// newCA creates a self-signed CA.
func newCA(t *testing.T, name pkix.Name) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := certificateTemplate(t, name, true)

	return &testCA{cert: createCertificate(t, tmpl, tmpl, key, key), key: key}
}

// issueCA creates an intermediate CA signed by ca.
func (ca *testCA) issueCA(t *testing.T, name pkix.Name) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cert := createCertificate(t, certificateTemplate(t, name, true), ca.cert, key, ca.key)

	return &testCA{cert: cert, key: key}
}

// issue creates a client certificate with a new key, signed by ca.
func (ca *testCA) issue(t *testing.T, name pkix.Name, emails ...string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := certificateTemplate(t, name, false)
	tmpl.EmailAddresses = emails

	return createCertificate(t, tmpl, ca.cert, key, ca.key)
}

// issueWithKey creates a client certificate for key, signed by ca.
func (ca *testCA) issueWithKey(t *testing.T, name pkix.Name, key crypto.Signer) *x509.Certificate {
	t.Helper()
	return createCertificate(t, certificateTemplate(t, name, false), ca.cert, key, ca.key)
}

func certificateTemplate(t *testing.T, name pkix.Name, isCA bool) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      name,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if isCA {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageCertSign
		tmpl.ExtKeyUsage = nil
	}

	return tmpl
}

func createCertificate(t *testing.T, tmpl, parent *x509.Certificate,
	key, parentKey crypto.Signer,
) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}
