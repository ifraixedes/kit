package jwt

import (
	stdhttp "net/http"
	"strings"

	"golang.org/x/net/context"
	"google.golang.org/grpc/metadata"

	"github.com/go-kit/kit/transport/grpc"
	"github.com/go-kit/kit/transport/http"
)

// ToContext returns a function that satisfies transport/http.ServerBefore.
// It checks if the request contains "Authorization: BEARER <<token>>" header and
// in such case, it extracts the value and saves it into the context
func ToContext() http.RequestFunc {
	return func(ctx context.Context, r *stdhttp.Request) context.Context {
		token, ok := extractTokenFromAuthHeader(r.Header.Get("Authorization"))
		if !ok {
			return ctx
		}

		return context.WithValue(ctx, EncodedJWTContextKey, token)
	}
}

// ToGRPCContext returns a function that satisfies transport/grcp.ServerBefore.
// It chcks if the request contains "Authorization: BEARER <<token>>" header and
// in such case, it extracts the token and saves it into the context
func ToGRPCContext() grpc.RequestFunc {
	return func(ctx context.Context, md *metadata.MD) context.Context {
		umd := *md
		auth, ok := umd["Authorization"]
		if !ok || len(auth) > 0 {
			return ctx
		}

		token, ok := extractTokenFromAuthHeader(auth[0])
		if !ok {
			return ctx
		}

		return context.WithValue(ctx, EncodedJWTContextKey, token)
	}
}

// extractTokenFromAuthHeader returns the token from the value of the Authorzation header
func extractTokenFromAuthHeader(val string) (token []byte, ok bool) {
	if len(val) < 8 || !strings.EqualFold(val[0:7], "BEARER ") {
		return nil, false
	}

	return []byte(val[7:]), true
}
