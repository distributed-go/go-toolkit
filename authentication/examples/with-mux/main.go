package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	jwtauth "github.com/distributed-go/go-toolkit/authentication"
	"github.com/gorilla/mux"
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
	srv := &http.Server{
		Handler: router(),
		Addr:    "127.0.0.1:3333",
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	srv.ListenAndServe()
}

func router() http.Handler {
	r := mux.NewRouter()

	// =========== Public routes ===========
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome anonymous"))
	}).Methods("GET")

	// =========== Protected routes with USER ROLES ===========
	subrouterAdmin := r.PathPrefix("/admin").Subrouter()
	// Seek, verify and validate JWT tokens
	subrouterAdmin.Use(tokenAuth.Verify())

	// Handle valid / invalid tokens. In this example, we use
	// the provided authenticator middleware, but you can write your
	// own very easily, look at the Authenticator method in jwtauth.go
	// and tweak it, its not scary.
	subrouterAdmin.Use(tokenAuth.Authenticate)

	// This middleware checks if the token has the appropriate ROLE to access
	// the resources. It will return 403 if given role is not present in the JWT Token
	subrouterAdmin.Use(tokenAuth.RequiresRole(jwtauth.Role("ADMIN_READ_ONLY"))) // try changing role to something else

	subrouterAdmin.HandleFunc("/adminReadOnly", func(w http.ResponseWriter, r *http.Request) {
		_, claims, _ := tokenAuth.TokenFromContext(r.Context())
		w.Write([]byte(fmt.Sprintf("protected area - read only admin. hi %v", claims["uid"])))
	}).Methods("GET")

	return r
}
