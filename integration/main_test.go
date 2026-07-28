//go:build integration

package integration_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/exec"
	"testing"
)

const binary = "extauthz"

var validConfig, policies, trustedSubjects, rsaPrivateKeyPEM string

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
}

func writeFiles(config, trustedSubjects, policies, rsaPrivateKeyPEM string) (func(), error) {
	// define the files to be created and their content
	files := map[string]string{
		"./config.yaml":          config,
		"./trustedSubjects.yaml": trustedSubjects,
		"./policies.cedar":       policies,
		"./keyId":                "key1",
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
		err := os.WriteFile(file, []byte(content), 0640)
		if err != nil {
			cleanupFunc() // clean up any files written before the error
			return nil, fmt.Errorf("could not write file: %v, got: %w", file, err)
		}
		cleanupFiles = append(cleanupFiles, file)
	}

	return cleanupFunc, nil
}

func buildCommandsAndRunTests(m *testing.M, cmds ...string) int {
	ctx := context.Background()

	// build the commands to be tested
	for _, name := range cmds {
		cmd := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-race", "-cover", "-o", name, "../cmd/"+name)
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("output: %s", output)
			log.Fatalf("error: %v", err)
		}
		defer os.Remove(name)
	}

	code := m.Run()
	return code
}

// serviceCmd builds the exec.Cmd for the service binary with its coverage output
// directed at EXTAUTHZ_COVERDIR (set by the Makefile). `go test` overrides
// GOCOVERDIR for the test binary to an internal temp dir that the subprocess
// would otherwise inherit and whose profile is discarded on exit, so the
// subprocess's coverage is only captured when we point it at the real dir
// explicitly.
func serviceCmd(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "./"+binary, args...)
	if dir := os.Getenv("EXTAUTHZ_COVERDIR"); dir != "" {
		cmd.Env = append(os.Environ(), "GOCOVERDIR="+dir)
	}
	return cmd
}

func TestMain(m *testing.M) {
	// put this in a function so we can use defer to clean up
	code := buildCommandsAndRunTests(m, binary)

	// exit with the code from the tests
	os.Exit(code)
}
