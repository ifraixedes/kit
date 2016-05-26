package jwt

import (
	"net/http"
	"testing"

	"google.golang.org/grpc/metadata"

	"golang.org/x/net/context"
)

func TestToContext(t *testing.T) {
	reqFunc := ToContext()

	// When the header doesn't exist
	ctx := reqFunc(context.Background(), &http.Request{})

	if ctx.Value(EncodedJWTContextKey) != nil {
		t.Error("Context shouldn't contain the encoded JWT")
	}

	// Authorization header value has invalid format
	header := http.Header{}
	header.Set("Authorization", "no expected auth header format value")
	ctx = reqFunc(context.Background(), &http.Request{Header: header})

	if ctx.Value(EncodedJWTContextKey) != nil {
		t.Error("Context shouldn't contain the encoded JWT")
	}

	// Authorization header is correct
	header.Set("Authorization", "bearer test")
	ctx = reqFunc(context.Background(), &http.Request{Header: header})

	encToken := ctx.Value(EncodedJWTContextKey).([]byte)
	if string(encToken) != "test" {
		t.Errorf("Context doesn't contain the expected encoded token value; expected: %s, got: %s")
	}
}

func TestToGRPCContext(t *testing.T) {
	reqFunc := ToGRPCContext()

	// When the header doesn't exist
	ctx := reqFunc(context.Background(), &metadata.MD{})

	if ctx.Value(EncodedJWTContextKey) != nil {
		t.Error("Context shouldn't contain the encoded JWT")
	}

	// Authorization header value has invalid format
	md := metadata.MD{}
	md["Authorization"] = []string{"no expected auth header format value"}
	ctx = reqFunc(context.Background(), &md)

	if ctx.Value(EncodedJWTContextKey) != nil {
		t.Error("Context shouldn't contain the encoded JWT")
	}

	// Authorization header is correct
	md["Authorization"] = []string{"bearer test"}
	ctx = reqFunc(context.Background(), &md)

	encToken := ctx.Value(EncodedJWTContextKey).([]byte)
	if string(encToken) != "test" {
		t.Errorf("Context doesn't contain the expected encoded token value; expected: %s, got: %s")
	}
}
