//go:build integration

package integration_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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

func writeFiles(config, trustedSubjects, policies, rsaPrivateKeyPEM string) (func(), error) {
	// define the files to be created and their content
	files := map[string]string{
		"./config.yaml":          config,
		"./trustedSubjects.yaml": trustedSubjects,
		"./policies.cedar":       policies,
		"./keyID.txt":            "key1",
		"./key1.pem":             rsaPrivateKeyPEM,
	}

	// prepare the cleanup function to later remove them
	cleanupFiles := []string{}
	cleanupFunc := func() {
		for _, file := range cleanupFiles {
			os.Remove(file)
		}
		cleanupFiles = cleanupFiles[:0]
	}

	// write the files and remember them for later cleanup
	for file, content := range files {
		if err := os.WriteFile(file, []byte(content), 0640); err != nil {
			cleanupFunc() // clean up any files written before the error
			return nil, fmt.Errorf("could not write file: %v, got: %s", file, err)
		}
		cleanupFiles = append(cleanupFiles, file)
	}

	return cleanupFunc, nil
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
