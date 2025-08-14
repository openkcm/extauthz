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
	// prepare the cleanup function to later remove files created during the test
	files := []string{}
	cleanupFunc := func() {
		for _, file := range files {
			os.Remove(file)
		}
	}

	// write config.yaml
	configFile := "./config.yaml"
	if err := os.WriteFile(configFile, []byte(config), 0640); err != nil {
		cleanupFunc() // clean up any files written before the error
		return cleanupFunc, fmt.Errorf("could not write file: %v, got: %s", configFile, err)
	}
	files = append(files, configFile)

	// write trustedSubjects.yaml
	trustedSubjectsYaml := "./trustedSubjects.yaml"
	if err := os.WriteFile(trustedSubjectsYaml, []byte(trustedSubjects), 0640); err != nil {
		cleanupFunc() // clean up any files written before the error
		return cleanupFunc, fmt.Errorf("could not write file: %v, got: %s", trustedSubjectsYaml, err)
	}
	files = append(files, trustedSubjectsYaml)

	// write polocies.cedar
	policiesFile := "./policies.cedar"
	if err := os.WriteFile(policiesFile, []byte(policies), 0640); err != nil {
		cleanupFunc() // clean up any files written before the error
		return cleanupFunc, fmt.Errorf("could not write file: %v, got: %s", policiesFile, err)
	}
	files = append(files, policiesFile)

	// write keyID.txt and key_1.priv
	privateKeyIDFile := "./keyID.txt"
	if err := os.WriteFile(privateKeyIDFile, []byte("key_1"), 0640); err != nil {
		cleanupFunc() // clean up any files written before the error
		return cleanupFunc, fmt.Errorf("could not write file: %v, got: %s", privateKeyIDFile, err)
	}
	files = append(files, privateKeyIDFile)
	privateKeyFile := "./key_1.priv"
	if err := os.WriteFile(privateKeyFile, []byte(rsaPrivateKeyPEM), 0640); err != nil {
		cleanupFunc() // clean up any files written before the error
		return cleanupFunc, fmt.Errorf("could not write file: %v, got: %s", privateKeyFile, err)
	}
	files = append(files, privateKeyFile)

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
