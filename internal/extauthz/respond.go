package extauthz

import (
	"encoding/json"
	"fmt"

	"github.com/gogo/googleapis/google/rpc"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"

	"github.com/openkcm/extauthz/internal/apierrors"
)

func headerValueOption(key, val string) *envoy_core.HeaderValueOption {
	return &envoy_core.HeaderValueOption{
		Header: &envoy_core.HeaderValue{
			Key:   key,
			Value: val,
		},
	}
}

func respondUnauthenticated(message string) (*envoy_auth.CheckResponse, error) {
	return deniedResponse(apierrors.New(apierrors.CodeAuthenticationRequired, message))
}

func respondTenantBlocked() (*envoy_auth.CheckResponse, error) {
	return deniedResponse(apierrors.New(apierrors.CodeTenantBlocked, "Tenant is blocked"))
}

func respondPermissionDenied() (*envoy_auth.CheckResponse, error) {
	return deniedResponse(apierrors.New(apierrors.CodeForbidden, "Permission denied"))
}

func respondAllowed(headers []*envoy_core.HeaderValueOption, headersToRemove []string) *envoy_auth.CheckResponse {
	return &envoy_auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &envoy_auth.CheckResponse_OkResponse{
			OkResponse: &envoy_auth.OkHttpResponse{
				Headers:         headers,
				HeadersToRemove: headersToRemove,
			},
		},
	}
}
func respondInternalServerError() (*envoy_auth.CheckResponse, error) {
	return deniedResponse(apierrors.New(apierrors.CodeInternalServerError, "Internal server error"))
}

func deniedResponse(e apierrors.Error) (*envoy_auth.CheckResponse, error) {
	type response struct {
		Error apierrors.Error `json:"error"`
	}

	r := response{Error: e}

	body, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("marshaling response: %w", err)
	}

	return &envoy_auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code:    int32(mapApiErrorToRPCCode(e)),
			Message: e.Message,
		},
		HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode(e.Status),
				},
				Headers: []*envoy_core.HeaderValueOption{
					{
						Header: &envoy_core.HeaderValue{
							Key:   "Content-Type",
							Value: "application/json",
						},
						AppendAction: envoy_core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
					},
				},
				Body: string(body),
			},
		},
	}, nil
}

func mapApiErrorToRPCCode(e apierrors.Error) rpc.Code {
	switch e.Code {
	case apierrors.CodeAuthenticationRequired:
		return rpc.UNAUTHENTICATED
	case apierrors.CodeTenantBlocked:
		return rpc.PERMISSION_DENIED
	case apierrors.CodeForbidden:
		return rpc.PERMISSION_DENIED
	case apierrors.CodeInternalServerError:
		return rpc.INTERNAL
	default:
		return rpc.UNKNOWN
	}
}
