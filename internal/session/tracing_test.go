package session

import (
	"context"
	"net"
	"testing"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/common-sdk/pkg/commongrpc"
	"github.com/openkcm/common-sdk/pkg/otlp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	sessionv1 "github.com/openkcm/api-sdk/proto/kms/api/cmk/sessionmanager/session/v1"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type tracingSessionServer struct {
	sessionv1.UnimplementedServiceServer

	metadata chan metadata.MD
}

func (s *tracingSessionServer) GetSession(ctx context.Context, req *sessionv1.GetSessionRequest) (*sessionv1.GetSessionResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.metadata <- md
	if req.GetSessionId() == "fail" {
		return nil, status.Error(codes.Internal, "session manager unavailable")
	}
	return &sessionv1.GetSessionResponse{Valid: true}, nil
}

func TestSessionRPCPropagatesW3CMetadata(t *testing.T) {
	previousProvider, previousPropagator := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	telemetryCtx, cancelTelemetry := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	require.NoError(t, otlp.Init(telemetryCtx, &commoncfg.Application{Name: "extauthz"}, &commoncfg.Telemetry{},
		&commoncfg.Logger{}, otlp.WithShutdownComplete(stopped)))
	provider, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider)
	require.True(t, ok)
	exporter := tracetest.NewInMemoryExporter()
	provider.RegisterSpanProcessor(sdktrace.NewSimpleSpanProcessor(exporter))
	t.Cleanup(func() {
		cancelTelemetry()
		<-stopped
		otel.SetTracerProvider(previousProvider)
		otel.SetTextMapPropagator(previousPropagator)
	})
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	service := &tracingSessionServer{metadata: make(chan metadata.MD, 1)}
	sessionv1.RegisterServiceServer(srv, service)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := commongrpc.NewClient(&commoncfg.GRPCClient{Address: "passthrough:///session"},
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }))
	require.NoError(t, err)
	manager, err := NewManager(conn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	ctx := otel.GetTextMapPropagator().Extract(t.Context(), propagation.MapCarrier{
		"traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-00",
		"tracestate":  "vendor=value", "baggage": "vendor=opaque",
	})
	_, err = manager.GetSession(ctx, "session-secret", "tenant")
	require.NoError(t, err)
	md := <-service.metadata
	require.Len(t, md.Get("traceparent"), 1)
	assert.Regexp(t, "^00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-[0-9a-f]{16}-00$", md.Get("traceparent")[0])
	assert.NotEqual(t, "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-00", md.Get("traceparent")[0])
	assert.Equal(t, []string{"vendor=value"}, md.Get("tracestate"))
	assert.Equal(t, []string{"vendor=opaque"}, md.Get("baggage"))
	assert.Empty(t, exporter.GetSpans(), "unsampled RPC is correlated but not exported")
	ctx = otel.GetTextMapPropagator().Extract(t.Context(), propagation.MapCarrier{
		"traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
	})
	_, err = manager.GetSession(ctx, "fail", "tenant")
	require.ErrorContains(t, err, "session manager unavailable", "preserve application error semantics")
	spans := exporter.GetSpans()
	require.Len(t, spans, 1, "sampled RPC must produce one span")
	assert.Equal(t, "session manager unavailable", spans[0].Status.Description)
}
