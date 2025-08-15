//go:build integration

package integration_test

import (
	"bytes"
	"io"
	"net/http"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestStatusServer(t *testing.T) {
	var err error

	// write files needed for the test
	cleanup, err := writeFiles(validConfig, trustedSubjects, policies, rsaPrivateKeyPEM)
	if err != nil {
		t.Fatalf("could not write files: %s", err)
	}
	defer cleanup()

	// start the service in the background
	cmd := exec.Command("./"+binary, "--graceful-shutdown=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatalf("could not start command: %s", err)
	}
	// defer the graceful stop of the service so that coverprofiles are written
	defer func() {
		syscall.Kill(cmd.Process.Pid, syscall.SIGTERM)
		cmd.Wait()
		t.Logf("Stdout: %s", stdout.String())
		t.Logf("Stderr: %s", stderr.String())
	}()

	// create the test cases
	tests := []struct {
		name       string
		endpoint   string
		wantOutput string
		wantError  bool
	}{
		{
			name:       "get version",
			endpoint:   "version",
			wantOutput: buildVersion,
			wantError:  false,
		},
	}

	// give the server some time to start before running the test
	for i := 100; i > 0; i-- {
		if i < 1 {
			t.Fatalf("could not connect to server: %s", err)
		}
		if _, err := http.Get("http://localhost:8080/"); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			resp, err := http.Get("http://localhost:8080/" + tc.endpoint)
			if err != nil {
				t.Fatalf("could not send request: %s", err)
			}
			defer resp.Body.Close()
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("could not read response body: %s", err)
			}

			// Assert
			if tc.wantError {
				if err == nil {
					t.Error("expected error, but got nil")
				}
				if got != nil {
					t.Errorf("expected nil response, but got: %+v", got)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				} else {
					if string(got) != tc.wantOutput {
						t.Errorf("expected: %s, got: %s", tc.wantOutput, got)
					}
				}
			}
		})
	}
}
