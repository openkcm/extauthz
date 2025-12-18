package extauthz

import (
	"github.com/gogo/googleapis/google/rpc"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
)

func headerValueOption(key, val string) *envoy_core.HeaderValueOption {
	return &envoy_core.HeaderValueOption{
		Header: &envoy_core.HeaderValue{
			Key:   key,
			Value: val,
		},
	}
}

func respondUnauthenticated(message string) *envoy_auth.CheckResponse {
	return &envoy_auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.UNAUTHENTICATED),
		},
		HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Unauthorized,
				},
				Body: message,
			},
		},
	}
}

func respondPermissionDenied() *envoy_auth.CheckResponse {
	return &envoy_auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.PERMISSION_DENIED),
		},
		HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Forbidden,
				},
				Body: "Permission denied",
			},
		},
	}
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
func respondInternalServerError() *envoy_auth.CheckResponse {
	return &envoy_auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.INTERNAL),
		},
		HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_InternalServerError,
				},
				Body: "Internal server error",
			},
		},
	}
}
