package jwt

import (
	"errors"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"golang.org/x/net/context"

	"github.com/go-kit/kit/endpoint"
)

const (
	// EncodedJWTContextKey holds the key used to store an encoded JWT in the context
	EncodedJWTContextKey = "EncodedJWT"
	// JWTContextKey holds the key used to store a JWT in the context
	JWTClaimsContextKey = "JWTClaims"
)

var (
	ErrTokenNotFound = errors.New("Token not present")
	ErrNotJWSToken   = errors.New("JWT isn't a JWS structures; JWE isn't supported")
	ErrNotJWT        = errors.New("Token is not a JWT")
	ErrNoKIDHeader   = errors.New("JWT token doens't have 'ki' header")
	ErrKIDNotFound   = errors.New("Not Found Key ID")
)

type KeySet map[string]struct {
	Method crypto.SigningMethod
	Key    []byte
}

// AuthenticateRequests returns a server.Middleware that extracts an JWT token from the
// context and verifies it, adding the claims, which contains, in the context or returning
// and error if it's invalid.
// KeySet identifies pairs of Signing methods and keys which can be used by the signer and
// an optional validator for custom validation
// See https://godoc.org/github.com/SermoDigital/jose/jwt#Validator
func AuthenticateRequests(keys KeySet, validators *jwt.Validator) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			encodedToken, ok = ctx.Value(JWTContextKey).([]byte)
			if !ok {
				return nil, ErrTokenNotFound
			}

			jwsToken, err := jws.ParseJWT(encodedToken)
			switch err {
			case nil:
			case jws.ErrHoldJWE:
				return nil, ErrNotJWSToken
			case jws.ErrIsNotJWT:
				return nil, ErrNotJWT
			default:
				return nil, err
			}

			// To avoid critical vulnerability related with "alg" header, we force the tokens
			// have the optional "kid" header and we ignore the value of "alg" header
			// See https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
			kid, ok := jwsToken.Protected()["kid"]
			if !ok {
				return nil, ErrNoKIDHeader
			}

			kEntry, ok := keys[kid]
			if !ok {
				return nil, ErrKIDNotFound
			}

			if validator == nil {
				err = jwsToken.Validate(kEntry.Key, kEntry.SigningMethod)
			} else {
				err = jwsToken.Validate(kEntry.Key, kEntry.SigningMethod, validator)
			}

			if err != nil {
				return nil, err
			}

			return next(context.WithValue(ctx, JWTClaimsContextKey, jwsToken.Claims()), request)
		}
	}
}
