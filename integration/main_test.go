//go:build integration

package integration_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const binary = "extauthz"

var validConfig, policies, trustedSubjects, rsaPrivateKeyPEM, buildVersion string

func init() {
	var err error
	var dat []byte

	// read config file
	dat, err = os.ReadFile("../examples/config.yaml")
	if err != nil {
		panic(err)
	}
	validConfig = string(dat)

	// read policies file
	dat, err = os.ReadFile("../examples/policies.cedar")
	if err != nil {
		panic(err)
	}
	policies = string(dat)

	// read trusted subjects file
	dat, err = os.ReadFile("../examples/trustedSubjects.yaml")
	if err != nil {
		panic(err)
	}
	trustedSubjects = string(dat)

	// generate a private key
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	rsaPrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(rsaPrivateKey)
	if err != nil {
		panic(err)
	}
	rsaPrivateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: rsaPrivateKeyDER,
	}))

	// read build_version.json file
	dat, err = os.ReadFile("../build_version.json")
	if err != nil {
		panic(err)
	}
	buildVersion = strings.TrimSpace(string(dat))
}

func buildCommandsAndRunTests(m *testing.M, cmds ...string) int {
	for _, name := range cmds {
		cmd := exec.Command("go", "build", "-buildvcs=false", "-race", "-cover", "-o", name, "../cmd/"+name)
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("output: %s", output)
			log.Fatalf("error: %v", err)
		}
		defer os.Remove(name)
	}

	code := m.Run()
	return code
}

func TestMain(m *testing.M) {
	// put this in a function so we can use defer to clean up
	code := buildCommandsAndRunTests(m, binary)

	// exit with the code from the tests
	os.Exit(code)
}
