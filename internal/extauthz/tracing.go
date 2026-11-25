package extauthz

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	envoycore "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

//nolint:spancheck // Check owns and ends the returned span after authorization.
func (srv *Server) startCheckSpan(ctx context.Context, headers map[string]string) (context.Context, trace.Span) {
	transport := trace.SpanContextFromContext(ctx)
	ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.MapCarrier(headers))
	parent := trace.SpanContextFromContext(ctx)
	opts := []trace.SpanStartOption{trace.WithSpanKind(trace.SpanKindServer)}
	if transport.IsValid() && parent.TraceID() != transport.TraceID() {
		opts = append(opts, trace.WithLinks(trace.Link{SpanContext: transport}))
	}
	ctx, span := srv.tracer.Start(ctx, spanNameCheck, opts...)
	return ctx, span
}

// replacementTraceHeaders supplies context only when the original HTTP request
// had no valid parent. Existing valid headers belong to the gateway's HTTP span
// and must remain unchanged when it forwards to the backend.
func replacementTraceHeaders(ctx context.Context, headers map[string]string) ([]*envoycore.HeaderValueOption, []string) {
	propagator := propagation.TraceContext{}
	original := propagator.Extract(context.Background(), propagation.MapCarrier(headers))
	if trace.SpanContextFromContext(original).IsValid() {
		return nil, nil
	}
	carrier := propagation.MapCarrier{}
	propagator.Inject(ctx, carrier)
	if carrier[HeaderTraceparent] == "" {
		return nil, nil
	}
	var added []*envoycore.HeaderValueOption
	for _, key := range []string{HeaderTraceparent, HeaderTracestate} {
		if value := carrier[key]; value != "" {
			header := headerValueOption(key, value)
			header.AppendAction = envoycore.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD
			added = append(added, header)
		}
	}
	if carrier[HeaderTracestate] == "" {
		return added, []string{HeaderTracestate}
	}
	return added, nil
}
