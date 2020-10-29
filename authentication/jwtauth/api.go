package jwtauth

import (
	"context"
	"errors"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// Library errors
var (
	ErrUnauthorized = errors.New("jwtauth: token is unauthorized")
	ErrExpired      = errors.New("jwtauth: token is expired")
	ErrNBFInvalid   = errors.New("jwtauth: token nbf validation failed")
	ErrIATInvalid   = errors.New("jwtauth: token iat validation failed")
	ErrNoTokenFound = errors.New("jwtauth: no token found")
	ErrAlgoInvalid  = errors.New("jwtauth: algorithm mismatch")
)

// Context keys
var (
	TokenCtxKey = &contextKey{"Token"}
	ErrorCtxKey = &contextKey{"Error"}
)

// JWTAuth implements the JWTAuth methods
type JWTAuth interface {
	// Middlewares for validating JWT tokens
	Authenticate(next http.Handler) http.Handler
	Verify() func(http.Handler) http.Handler

	// Functions to extract tokens from http request
	TokenFromCookie(r *http.Request) string
	TokenFromHeader(r *http.Request) string
	TokenFromQuery(r *http.Request) string

	// Functions to encode and decode tokens
	Encode(claims jwt.Claims) (t *jwt.Token, tokenString string, err error)
	Decode(tokenString string) (t *jwt.Token, err error)

	// Functions to work with context
	TokenFromContext(ctx context.Context) (*jwt.Token, jwt.MapClaims, error)
	NewContext(ctx context.Context, t *jwt.Token, err error) context.Context

	// Utility functions for setting token expiry
	ExpireIn(tm time.Duration) int64
	SetIssuedAt(claims jwt.MapClaims, tm time.Time)
	SetIssuedNow(claims jwt.MapClaims)
	SetExpiry(claims jwt.MapClaims, tm time.Time)
	SetExpiryIn(claims jwt.MapClaims, tm time.Duration)
}
