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
			Key:    []byte("go-kit-secret-256"),
		},
		"hs512": {
			Method: &crypto.SigningMethodHMAC{Name: "HS512", Hash: stdcrypto.SHA512},
			Key:    []byte("go-kit-secret-512"),
		},
	}
	authEndPoint := AuthenticateRequests(keys, nil)(returnCtxEndpoint)

	// Call middleware without token
	_, err := authEndPoint(context.Background(), nil)
	if err == nil {
		t.Error("Expected error returned not to be nil")
	}

	if err != ErrTokenNotFound {
		t.Errorf("Returned errors isn't the one expected; expect: %s, got: %s", ErrTokenNotFound.Error(), err.Error())
	}

	// Send token without "kid"
	pheader := jose.Header{}
	claims := jws.Claims{"name": "test"}
	token := createJWTToken(t, keys["hs256"].Key, keys["hs256"].Method, pheader, claims)

	_, err = authEndPoint(context.WithValue(context.Background(), EncodedJWTContextKey, token), nil)
	if err == nil {
		t.Error("Expected error returned not to be nil")
	}

	if err != ErrNoKIDHeader {
		t.Errorf("Returned errors isn't the one expected; expect: %s, got: %s", ErrNoKIDHeader.Error(), err.Error())
	}

	// Send token with wrong "kid" header value
	pheader = jose.Header{"kid": "hs512"}
	claims = jws.Claims{"name": "test"}
	token = createJWTToken(t, keys["hs256"].Key, keys["hs256"].Method, pheader, claims)

	_, err = authEndPoint(context.WithValue(context.Background(), EncodedJWTContextKey, token), nil)
	if err == nil {
		t.Error("Expected error returned not to be nil")
	}

	// Send token with an unexisting "kid"
	pheader = jose.Header{"kid": "not-exist"}
	claims = jws.Claims{"name": "test"}
	token = createJWTToken(t, keys["hs256"].Key, keys["hs256"].Method, pheader, claims)

	_, err = authEndPoint(context.WithValue(context.Background(), EncodedJWTContextKey, token), nil)
	if err == nil {
		t.Error("Expected error returned not to be nil")
	}

	if err != ErrKIDNotFound {
		t.Errorf("Returned errors isn't the one expected; expect: %s, got: %s", ErrKIDNotFound.Error(), err.Error())
	}

	// Send token with wrong "kid" header value
	pheader = jose.Header{"kid": "hs512"}
	claims = jws.Claims{"name": "test"}
	token = createJWTToken(t, keys["hs256"].Key, keys["hs256"].Method, pheader, claims)

	_, err = authEndPoint(context.WithValue(context.Background(), EncodedJWTContextKey, token), nil)
	if err == nil {
		t.Error("Expected error returned not to be nil")
	}

	// Send token with invalid "kid"
	pheader = jose.Header{"kid": 256}
	claims = jws.Claims{"name": "test"}
	token = createJWTToken(t, keys["hs256"].Key, keys["hs256"].Method, pheader, claims)

	_, err = authEndPoint(context.WithValue(context.Background(), EncodedJWTContextKey, token), nil)
	if err == nil {
		t.Error("Expected error returned not to be nil")
	}

	if err != ErrInvalidKIDValue {
		t.Errorf("Returned errors isn't the one expected; expect: %s, got: %s", ErrInvalidKIDValue.Error(), err.Error())
	}

	// Send an invalid token
	pheader = jose.Header{"kid": "hs256"}
	claims = jws.Claims{"name": "test"}
	token = createJWTInvalidToken(t, keys["hs256"].Key, keys["hs256"].Method, pheader, claims)

	_, err = authEndPoint(context.WithValue(context.Background(), EncodedJWTContextKey, token), nil)
	if err == nil {
		t.Error("Expected error returned not to be nil")
	}

	// Successful case for HS256
	pheader = jose.Header{"kid": "hs256"}
	claims = jws.Claims{"name": "test"}
	token = createJWTToken(t, keys["hs256"].Key, keys["hs256"].Method, pheader, claims)

	resp, err := authEndPoint(context.WithValue(context.Background(), EncodedJWTContextKey, token), nil)
	if err != nil {
		t.Fatalf("Unexpected error returned: %s", err.Error())
	}

	epCtx := resp.(context.Context)
	cl := getClaimsFromContext(t, epCtx)
	nameValue := getStringClaim(t, cl, "name")
	if nameValue != "test" {
		t.Errorf("Invalid 'name' value; expect: test, got: %s ", nameValue)
	}

	// Successful case for HS512
	pheader = jose.Header{"kid": "hs512"}
	claims = jws.Claims{"name": "test", "bits": 512}
	token = createJWTToken(t, keys["hs512"].Key, keys["hs512"].Method, pheader, claims)

	resp, err = authEndPoint(context.WithValue(context.Background(), EncodedJWTContextKey, token), nil)
	if err != nil {
		t.Fatalf("Unexpected error returned: %s", err.Error())
	}

	epCtx = resp.(context.Context)
	cl = getClaimsFromContext(t, epCtx)
	nameValue = getStringClaim(t, cl, "name")
	if nameValue != "test" {
		t.Errorf("Invalid 'name' value; expect: test, got: %s ", nameValue)
	}

	bitsValue := getFloatClaim(t, cl, "bits")
	if int(bitsValue) != 512 {
		t.Errorf("Invalid 'bits' value; expect: 512, got: %d ", int(bitsValue))
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

func createJWTInvalidToken(t *testing.T, key []byte, method crypto.SigningMethod, protected jose.Header, claims jws.Claims) []byte {
	jwsToken := jws.New(claims, method)

	ph := jwsToken.Protected()
	ph.Set("typ", "JWT")
	for k, v := range protected {
		ph.Set(k, v)
	}

	encodedToken, err := jwsToken.Flat(key) // This encoding isn't accepted by JWT
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

func getFloatClaim(t *testing.T, cl Claims, key string) float64 {
	_, ok := cl[key]
	if !ok {
		t.Errorf("Claims in the context doens't contain the a value for %s key", key)
	}

	val, ok := cl[key].(float64)
	if !ok {
		t.Errorf("Expected to find %s to be an int in the claims", key)
	}

	return val
}
