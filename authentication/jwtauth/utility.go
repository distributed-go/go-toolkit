package jwtauth

import (
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// TokenFromCookie tries to retreive the token string from a cookie named
// "jwt".
func (ja *jwtAuth) TokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie("jwt")
	if err != nil {
		return ""
	}
	return cookie.Value
}

// TokenFromHeader tries to retreive the token string from the
// "Authorization" request header: "Authorization: BEARER T".
func (ja *jwtAuth) TokenFromHeader(r *http.Request) string {
	// Get token from authorization header.
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}
	return ""
}

// TokenFromQuery tries to retreive the token string from the "jwt" URI
// query parameter.
func (ja *jwtAuth) TokenFromQuery(r *http.Request) string {
	// Get token from query param named "jwt".
	return r.URL.Query().Get("jwt")
}

// UnixTime returns the given time in UTC milliseconds
func unixTime(tm time.Time) int64 {
	return tm.UTC().Unix()
}

// EpochNow is a helper function that returns the NumericDate time value used by the spec
func epochNow() int64 {
	return time.Now().UTC().Unix()
}

// ExpireIn is a helper function to return calculated time in the future for "exp" claim
func expireIn(tm time.Duration) int64 {
	return epochNow() + int64(tm.Seconds())
}

// SetIssuedAt issued at ("iat") to specified time in the claims
func setIssuedAt(claims jwt.MapClaims, tm time.Time) {
	claims["iat"] = tm.UTC().Unix()
}

// SetIssuedNow issued at ("iat") to present time in the claims
func setIssuedNow(claims jwt.MapClaims) {
	claims["iat"] = epochNow()
}

// SetExpiry expiry ("exp") in the claims
func setExpiry(claims jwt.MapClaims, tm time.Time) {
	claims["exp"] = tm.UTC().Unix()
}

// SetExpiryIn expiry ("exp") in the claims to some duration from the present time
func setExpiryIn(claims jwt.MapClaims, tm time.Duration) {
	claims["exp"] = expireIn(tm)
}

func (ja *jwtAuth) keyFunc(t *jwt.Token) (interface{}, error) {
	if ja.verifyKey != nil {
		return ja.verifyKey, nil
	} else {
		return ja.signKey, nil
	}
}

func (ja *jwtAuth) Encode(claims jwt.Claims) (t *jwt.Token, tokenString string, err error) {
	t = jwt.New(ja.signer)
	t.Claims = claims
	tokenString, err = t.SignedString(ja.signKey)
	t.Raw = tokenString
	return
}

func (ja *jwtAuth) Decode(tokenString string) (t *jwt.Token, err error) {
	t, err = ja.parser.Parse(tokenString, ja.keyFunc)
	if err != nil {
		return nil, err
	}
	return
}
