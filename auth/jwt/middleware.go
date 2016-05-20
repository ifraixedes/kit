package jwt

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/net/context"

	"github.com/go-kit/kit/endpoint"
)

const (
	// JWTContextKey holds the key used to store JWT in the context
	JWTContextKey = "JWT"
)

var ErrTokenNotFound = errors.New("Token not present")
var ErrExpiredToken = errors.New("Token expired")
var ErrInvalidToken = errors.New("Token is invalid")

func AuthenticateRequests(keyfunc jwt.Keyfunc) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			token, ok = ctx.Value(JWTContextKey).(string)
			if !ok {
				return nil, ErrTokenNotFound
			}

			if err := validate(token, keyfunc); err != nil {
				return err
			}

			return next(ctx, request)
		}
	}
}

func validate(token string, keyfunc jw.Keyfunc) error {
	ptoken, err := jwt.Parse(token, keyfunc)
	if err != nil {
		verr, ok := err.(*jwt.ValidationError)
		if !ok {
			return err
		}

		if verr.Errors == jwt.ValidationErrorExpired {
			return ErrExpiredToken
		}

		// TODO evalute if expose fine grain errors github.com/dgrijalva/jwt-go/errors.go
		return verr.Inner
	}

	if !ptoken.Valid {
		return ErrInvalidToken
	}

	return nil
}
