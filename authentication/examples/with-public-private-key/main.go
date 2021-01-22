// ubuntu@ubuntu-VirtualBox:~$ curl -v http://localhost:3333/
// *   Trying 127.0.0.1...
// * TCP_NODELAY set
// * Connected to localhost (127.0.0.1) port 3333 (#0)
// > GET / HTTP/1.1
// > Host: localhost:3333
// > User-Agent: curl/7.58.0
// > Accept: */*
// >
// < HTTP/1.1 200 OK
// < Date: Tue, 19 Jan 2021 10:19:38 GMT
// < Content-Length: 17
// < Content-Type: text/plain; charset=utf-8
// <
// * Connection #0 to host localhost left intact
// welcome anonymous

// ubuntu@ubuntu-VirtualBox:~$ curl -v http://localhost:3333/admin/adminReadOnly
// *   Trying 127.0.0.1...
// * TCP_NODELAY set
// * Connected to localhost (127.0.0.1) port 3333 (#0)
// > GET /admin/adminReadOnly HTTP/1.1
// > Host: localhost:3333
// > User-Agent: curl/7.58.0
// > Accept: */*
// >
// < HTTP/1.1 401 Unauthorized
// < Content-Type: text/plain; charset=utf-8
// < X-Content-Type-Options: nosniff
// < Date: Tue, 19 Jan 2021 10:29:57 GMT
// < Content-Length: 13
// <
// Unauthorized
// * Connection #0 to host localhost left intact

// ubuntu@ubuntu-VirtualBox:~$ curl -H"Authorization: BEARER eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiIxMjMiLCJuYW1lIjoiTWlrZSBKU09OIiwicm9sZXMiOlsiVVNFUiIsIkFETUlOX1JFQURfT05MWSJdLCJleHAiOjE2MTEwNTI3NzQsImlhdCI6MTYxMTA1MjE3NH0.MD8npUtLNC88sEc8TobfGTKiIaovlQkmgqYheXZrhJE" -v http://localhost:3333/admin/adminReadOnly
// *   Trying 127.0.0.1...
// * TCP_NODELAY set
// * Connected to localhost (127.0.0.1) port 3333 (#0)
// > GET /admin/adminReadOnly HTTP/1.1
// > Host: localhost:3333
// > User-Agent: curl/7.58.0
// > Accept: */*
// > Authorization: BEARER eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiIxMjMiLCJuYW1lIjoiTWlrZSBKU09OIiwicm9sZXMiOlsiVVNFUiIsIkFETUlOX1JFQURfT05MWSJdLCJleHAiOjE2MTEwNTI3NzQsImlhdCI6MTYxMTA1MjE3NH0.MD8npUtLNC88sEc8TobfGTKiIaovlQkmgqYheXZrhJE
// >
// < HTTP/1.1 200 OK
// < Date: Tue, 19 Jan 2021 10:31:36 GMT
// < Content-Length: 40
// < Content-Type: text/plain; charset=utf-8
// <
// * Connection #0 to host localhost left intact
// protected area - read only admin. hi 123

package main

import (
	"fmt"
	"net/http"
	"log"
	"os"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/dgrijalva/jwt-go"
	jwtauth "github.com/distributed-go/go-toolkit/authentication"
	"github.com/gorilla/mux"
)

var (
	tokenAuth jwtauth.JWTAuth

	privateKeyRS256String = `-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBALxo3PCjFw4QjgOX06QCJIJBnXXNiEYwDLxxa5/7QyH6y77nCRQy
J3x3UwF9rUD0RCsp4sNdX5kOQ9PUyHyOtCUCAwEAAQJARjFLHtuj2zmPrwcBcjja
IS0Q3LKV8pA0LoCS+CdD+4QwCxeKFq0yEMZtMvcQOfqo9x9oAywFClMSlLRyl7ng
gQIhAOyerGbcdQxxwjwGpLS61Mprf4n2HzjwISg20cEEH1tfAiEAy9dXmgQpDPir
C6Q9QdLXpNgSB+o5CDqfor7TTyTCovsCIQDNCfpu795luDYN+dvD2JoIBfrwu9v2
ZO72f/pm/YGGlQIgUdRXyW9kH13wJFNBeBwxD27iBiVj0cbe8NFUONBUBmMCIQCN
jVK4eujt1lm/m60TlEhaWBC3p+3aPT2TqFPUigJ3RQ==
-----END RSA PRIVATE KEY-----
`

	publicKeyRS256String = `-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALxo3PCjFw4QjgOX06QCJIJBnXXNiEYw
DLxxa5/7QyH6y77nCRQyJ3x3UwF9rUD0RCsp4sNdX5kOQ9PUyHyOtCUCAwEAAQ==
-----END PUBLIC KEY-----
`
)

func init() {
	privateKeyBlock, _ := pem.Decode([]byte(privateKeyRS256String))
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		log.Fatalf(err.Error())
	}

	publicKeyBlock, _ := pem.Decode([]byte(publicKeyRS256String))
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		log.Fatalf(err.Error())
	}


	tokenAuth = jwtauth.NewJWTAuth(jwtauth.Config{
		JwtAuthAlgo:      "RS256",
		JwtParser:        &jwt.Parser{},
		SignKey:          privateKey,
		VerifyKey:        publicKey,
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
