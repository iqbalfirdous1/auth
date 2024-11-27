package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("secret_key")

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type TokenResponse struct {
	Token string `json:"token"`
}

// Login handler: validates credentials and generates a JWT token
func Login(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Validate the user's credentials
	expectedPassword, ok := users[credentials.Username]
	if !ok || expectedPassword != credentials.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Generate a JWT token that expires in 5 minutes
	expirationTime := time.Now().Add(time.Minute * 5)
	claims := &Claims{
		Username: credentials.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Respond with the generated token
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(TokenResponse{Token: tokenString})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// Welcome handler: a protected route that requires a valid JWT token
func Welcome(w http.ResponseWriter, r *http.Request) {
	// Extract the token from the Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Remove "Bearer " from the header value to extract the token
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse and validate the token
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	// If the token is invalid or parsing fails, return Unauthorized
	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// If the token is valid, respond with a welcome message
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Welcome, %s! You are authorized to access this route.", claims.Username)
}

func main() {
	// Route for login: will return a JWT token
	http.HandleFunc("/login", Login)

	// Route for welcome: requires a valid JWT token in the Authorization header
	http.HandleFunc("/welcome", Welcome)

	// Start the server on port 8080
	http.ListenAndServe(":8080", nil)
}
