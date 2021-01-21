package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	jwtauth "github.com/distributed-go/go-toolkit/authentication"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var tokenAuth jwtauth.JWTAuth
var tokenSecret = []byte("secretpass")

func init() {
	tokenAuth = jwtauth.NewJWTAuth(jwtauth.Config{
		JwtAuthAlgo:      "HS256",
		JwtParser:        &jwt.Parser{},
		SignKey:          tokenSecret,
		VerifyKey:        nil,
		JwtExpiry:        time.Minute * 10,
		JwtRefreshExpiry: time.Minute * 60,
	})

	// For debugging/example purposes, we generate and print
	// a sample jwt token with claims `user_id:123` here:
	accessToken, refreshToken, err := tokenAuth.GenTokenPair(&jwtauth.AppClaims{
		UserID: "123",
		Name:   "Mike JSON",
		Roles:  []jwtauth.Role{jwtauth.Role("USER"), jwtauth.Role("ADMIN_READ_ONLY")},
	}, &jwtauth.RefreshClaims{
		UserID: "123",
		Roles:  []jwtauth.Role{jwtauth.Role("USER"), jwtauth.Role("ADMIN_READ_ONLY")},
	})
	if err != nil {
		fmt.Println("ERROR: ", err)
		os.Exit(1)
	}
	fmt.Printf("AccessToken: %s \nRefreshToken: %s \n", accessToken, refreshToken)
}

func main() {
	// Echo instance
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// =========== Public routes ===========
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "welcome anonymous")
	})

	// Start server
	e.Logger.Fatal(e.Start("127.0.0.1:3333"))
}
