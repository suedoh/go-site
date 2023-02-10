package authentication

import (
	"errors"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/csrf"
)

// NewAuth returns a new Auth middleware with the given config
func NewAuth(config Config) *Auth {
	return &Auth{config}
}

// AuthMiddleware is a middleware that validates the JWT token
func (a *Auth) AuthMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// get the cookie
		c, err := r.Cookie("token")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// validate the token
		claims, err := a.ValidateJWT(c.Value)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// set the claims in the request context
		ctx := r.Context()
		ctx = context.WithValue(ctx, claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
    var user User

    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, "Error decoding JSON", http.StatusBadRequest)
        return
    }

    if !a.checkUser(user) {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // create JWT token
    token, err := a.createJWT(user)
    if err != nil {
        http.Error(w, "Error creating JWT", http.StatusInternalServerError)
        return
    }

    http.SetCookie(w, &http.Cookie{
        Name:    "token",
        Value:   token,
        Expires: time.Now().Add(time.Minute * 15),
    })
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
    // Clear the cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "token",
        Value:    "",
        Expires:  time.Now(),
        HttpOnly: true,
    })

    // Redirect to the login page
    http.Redirect(w, r, "/login", http.StatusSeeOther)
}

