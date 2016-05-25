package jwt

import (
	stdcrypto "crypto"
	"testing"

	"golang.org/x/net/context"

	"github.com/SermoDigital/jose"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
)

func TestAuthenticateRequests(t *testing.T) {
	keys := KeySet{
		"hs256": {
			Method: &crypto.SigningMethodHMAC{Name: "HS256", Hash: stdcrypto.SHA256},
			Key:    []byte("go-kit-secret"),
		},
	}

	pheader := jose.Header{"kid": "hs256"}
	claims := jws.Claims{"name": "test"}
	token := createJWTToken(t, keys["hs256"].Key, keys["hs256"].Method, pheader, claims)

	authEndPoint := AuthenticateRequests(keys, nil)(returnCtxEndpoint)
	resp, err := authEndPoint(context.WithValue(context.Background(), EncodedJWTContextKey, token), nil)
	if err != nil {
		t.Fatalf("Unexpected error returned: %s", err.Error())
	}

	epCtx := resp.(context.Context)
	cl := getClaimsFromContext(t, epCtx)
	nameValue := getStringClaim(t, cl, "name")
	if nameValue != "test" {
		t.Errorf("Invalid 'name' value; want: test, got: %s ", nameValue)
	}
}

func createJWTToken(t *testing.T, key []byte, method crypto.SigningMethod, protected jose.Header, claims jws.Claims) []byte {
	jwsToken := jws.New(claims, method)

	ph := jwsToken.Protected()
	ph.Set("typ", "JWT")
	for k, v := range protected {
		ph.Set(k, v)
	}

	encodedToken, err := jwsToken.Compact(key)
	if err != nil {
		t.Fatalf("Create JWT Token has failed; %s", err.Error())
	}

	return encodedToken
}

func returnCtxEndpoint(ctx context.Context, request interface{}) (interface{}, error) {
	return ctx, nil
}

func getClaimsFromContext(t *testing.T, ctx context.Context) Claims {
	clv := ctx.Value(JWTClaimsContextKey)

	if clv != nil {
		cl, ok := clv.(Claims)
		if !ok {
			t.Fatalf("Context should contains a Claims type value")
			return nil
		}

		return cl
	}

	t.Fatalf("Context doens't contain the token claims")
	return nil
}

func getStringClaim(t *testing.T, cl Claims, key string) string {
	_, ok := cl[key]
	if !ok {
		t.Errorf("Claims in the context doens't contain the a value for %s key", key)
	}

	val, ok := cl[key].(string)
	if !ok {
		t.Errorf("Expected to find %s to be a string in the claims", key)
	}

	return val
}
