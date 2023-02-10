package authentication

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Config holds the configuration for the JWT
type Config struct {
	SecretKey  []byte
	Expiration time.Duration
}

// Auth is the struct for the auth middleware
type Auth struct {
	cfg    *Config
	secret []byte
}

// AuthMiddleware is the middleware for handling auth
func (a *Auth) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Token is missing", http.StatusBadRequest)
			return
		}

		claims, err := ValidateJWT(tokenString, a.cfg.SecretKey)
		if err != nil {
			http.Error(w, "Token is invalid", http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "username", claims.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Login handles the login of a user
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	// Parse the request body to get the user login credentials
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Check if the provided username and password match the hardcoded values
	if user.Username != "test" || user.Password != "password" {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Create a new JWT token and set it as the HTTP only session cookie
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(a.secret))
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   tokenString,
		Expires: expirationTime,
		HttpOnly: true,
	})
	json.NewEncoder(w).Encode(map[string]string{"message": "Successfully logged in"})
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Now(),
		HttpOnly: true,
	})
	json.NewEncoder(w).Encode(map[string]string{"message": "Successfully logged out"})
}

func (a *Auth) ValidateJWT(token string) error {
	// Parse the token
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return a.SigningKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return err
		}
		return err
	}
	if !tkn.Valid {
		return errors.New("Invalid token")
	}
	return nil
}

// RefreshHandler refreshes the JWT token
func (a *Auth) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	// TODO
}

// LogoutHandler expires the JWT token
func (a *Auth) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// TODO
}

