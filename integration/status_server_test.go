//go:build integration

package integration_test

import (
	"bytes"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestStatusServer(t *testing.T) {
	// write files needed for the test
	cleanup, err := writeFiles(validConfig, trustedSubjects, policies, rsaPrivateKeyPEM)
	if err != nil {
		t.Fatalf("could not write files: %s", err)
	}
	defer cleanup()

	// start the service in the background
	cmd := exec.CommandContext(t.Context(), "./"+binary, "--graceful-shutdown=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Start()
	if err != nil {
		t.Fatalf("could not start command: %s", err)
	}
	// defer the graceful stop of the service so that coverprofiles are written
	defer func() {
		_ = syscall.Kill(cmd.Process.Pid, syscall.SIGTERM)
		_ = cmd.Wait()
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
			wantOutput: "{}",
			wantError:  false,
		}, {
			name:       "get readiness",
			endpoint:   "probe/readiness",
			wantOutput: "",
			wantError:  false,
		}, {
			name:       "get liveness",
			endpoint:   "probe/liveness",
			wantOutput: "",
			wantError:  false,
		},
	}

	// give the server some time to start before running the test
	for i := 100; i > 0; i-- {
		if i < 1 {
			t.Fatalf("could not connect to server: %s", err)
		}
		req, reqErr := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/", nil)
		if reqErr != nil {
			t.Fatalf("could not build request: %s", reqErr)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/"+tc.endpoint, nil)
			if err != nil {
				t.Fatalf("could not build request: %s", err)
			}
			resp, err := http.DefaultClient.Do(req)
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
					t.Logf("response: %s", got)
					if tc.wantOutput != "" && strings.TrimSpace(string(got)) != strings.TrimSpace(tc.wantOutput) {
						t.Errorf("expected: %s, got: %s", tc.wantOutput, got)
					}
				}
			}
		})
	}
}
