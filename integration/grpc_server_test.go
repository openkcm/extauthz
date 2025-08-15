//go:build integration

package integration_test

import (
	"bytes"
	"os/exec"
	"syscall"
	"testing"
	"time"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/gogo/googleapis/google/rpc"
	"google.golang.org/grpc"
)

func TestCheck(t *testing.T) {
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
		t.Logf("Stdout: %s\n", stdout.String())
		t.Logf("Stderr: %s\n", stderr.String())
	}()

	// create the gRPC based authorization client
	conn, err := grpc.NewClient("localhost:9092", grpc.WithInsecure())
	if err != nil {
		t.Fatalf("could not connect to server: %s", err)
	}
	client := envoy_auth.NewAuthorizationClient(conn)

	// create the test cases
	tests := []struct {
		name      string
		request   *envoy_auth.CheckRequest
		wantError bool
		wantCode  rpc.Code
	}{
		{
			name:      "zero values",
			request:   &envoy_auth.CheckRequest{},
			wantError: false,
			wantCode:  rpc.UNAUTHENTICATED,
		},
	}

	// give the server some time to start before running the test
	for i := 100; i > 0; i-- {
		if i < 1 {
			t.Fatalf("could not connect to server: %s", err)
		}
		if _, err := client.Check(t.Context(), nil); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got, err := client.Check(t.Context(), tc.request)

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
					if got.GetStatus().GetCode() != int32(tc.wantCode) {
						t.Errorf("expected status code %d, but got: %d", tc.wantCode, got.GetStatus().GetCode())
					}
				}
			}
		})
	}
}
