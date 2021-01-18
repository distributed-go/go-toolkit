package jwtauth

import (
	"context"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
)

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation. This technique
// for defining context keys was copied from Go 1.7's new use of context in net/http.
type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "jwtauth context value " + k.name
}

// TokenFromContext extracts the JWT token from the request context
func (ja *jwtAuth) TokenFromContext(ctx context.Context) (*jwt.Token, jwt.MapClaims, error) {
	token, _ := ctx.Value(TokenCtxKey).(*jwt.Token)

	var claims jwt.MapClaims
	if token != nil {
		if tokenClaims, ok := token.Claims.(jwt.MapClaims); ok {
			claims = tokenClaims
		} else {
			panic(fmt.Sprintf("jwtauth: unknown type of Claims: %T", token.Claims))
		}
	} else {
		claims = jwt.MapClaims{}
	}

	err, _ := ctx.Value(ErrorCtxKey).(error)

	return token, claims, err
}

// NewContext creates a new context with JWT token and error
func (ja *jwtAuth) NewContext(ctx context.Context, t *jwt.Token, err error) context.Context {
	ctx = context.WithValue(ctx, TokenCtxKey, t)
	ctx = context.WithValue(ctx, ErrorCtxKey, err)
	return ctx
}

// AppClaimsFromCtx retrieves the parsed AppClaims from request context.
func (ja *jwtAuth) AppClaimsFromCtx(ctx context.Context) AppClaims {
	return ctx.Value(AccessClaimsCtxKey).(AppClaims)
}
