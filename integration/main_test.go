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
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/testcontainers/testcontainers-go"

	tcvalkey "github.com/testcontainers/testcontainers-go/modules/valkey"
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
		if err := os.WriteFile(file, []byte(content), 0640); err != nil {
			cleanupFunc() // clean up any files written before the error
			return nil, fmt.Errorf("could not write file: %v, got: %s", file, err)
		}
		cleanupFiles = append(cleanupFiles, file)
	}

	return cleanupFunc, nil
}

func buildCommandsAndRunTests(m *testing.M, cmds ...string) int {
	// start a valkey container for the tests
	valkeyContainer, address, err := startValkeyContainer()
	if err != nil {
		log.Fatalf("error starting valkey container: %v", err)
	}
	defer func() {
		if err := testcontainers.TerminateContainer(valkeyContainer); err != nil {
			log.Printf("failed to terminate container: %s", err)
		}
	}()

	// adjust the config to use the valkey container port
	validConfig = strings.ReplaceAll(validConfig, "localhost:6379", address)

	// build the commands to be tested
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

func startValkeyContainer() (*tcvalkey.ValkeyContainer, string, error) {
	ctx := context.Background()

	// start a valkey container for the tests
	valkeyContainer, err := tcvalkey.Run(ctx,
		"docker.io/valkey/valkey:7.2.5",
		tcvalkey.WithLogLevel(tcvalkey.LogLevelVerbose),
	)
	if err != nil {
		return nil, "", fmt.Errorf("error starting valkey container: %v", err)
	}
	connstr, err := valkeyContainer.ConnectionString(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("error getting valkey container connection string: %v", err)
	}
	uri, err := url.Parse(connstr)
	if err != nil {
		return nil, "", fmt.Errorf("error parsing valkey container connection string: %v", err)
	}

	return valkeyContainer, uri.Host, nil
}
