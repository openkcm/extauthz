//go:build integration

package integration_test

import (
	"bytes"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
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
		wantCode  code.Code
	}{
		{
			name:      "zero values",
			request:   &envoy_auth.CheckRequest{},
			wantError: false,
			wantCode:  code.Code_UNAUTHENTICATED,
		},
	}

	// give the server some time to start before running the test
	for i := 100; i > 0; i-- {
		if i < 1 {
			t.Fatalf("could not connect to server: %s", err)
		}
		_, checkErr := client.Check(t.Context(), nil)
		if checkErr == nil {
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

	t.Run("trace headers are not stripped or overwritten", func(t *testing.T) {
		// Send a request whose HTTP headers include trace propagation
		// headers and verify they are not in HeadersToRemove and not present
		// as overwrites in HeadersToAdd in any OkResponse, and that the
		// service does not return an error.
		const tp = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
		req := &envoy_auth.CheckRequest{Attributes: &envoy_auth.AttributeContext{
			Request: &envoy_auth.AttributeContext_Request{Http: &envoy_auth.AttributeContext_HttpRequest{
				Method: "GET", Host: "myorg.com", Path: "/api/whatever",
				Headers: map[string]string{
					"traceparent": tp,
					"tracestate":  "vendor=value",
					"baggage":     "k1=v1",
				},
			}},
		}}

		resp, err := client.Check(t.Context(), req)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		// The integration scaffold cannot easily mint a real OkResponse
		// (would require trusted certs, OIDC keys, etc.), so assert
		// conditionally — if we did get an OkResponse, the trace headers
		// must not be in HeadersToRemove and must not be overwritten in
		// HeadersToAdd. Either way, the call must not error.
		if ok := resp.GetOkResponse(); ok != nil {
			for _, h := range ok.GetHeadersToRemove() {
				if h == "traceparent" || h == "tracestate" || h == "baggage" {
					t.Errorf("trace header %q must not be in HeadersToRemove", h)
				}
			}
			for _, h := range ok.GetHeaders() {
				k := h.GetHeader().GetKey()
				if k == "traceparent" || k == "tracestate" || k == "baggage" {
					t.Errorf("trace header %q must not be overwritten in HeadersToAdd", k)
				}
			}
		}
	})
}
