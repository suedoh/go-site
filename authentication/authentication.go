package authentication

import (
	"net/http"

	"github.com/suedoh/go-site/auth"
)

// LoginHandler handles the login route
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Call the Login function in auth package
	err := auth.Login(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to protected page
	http.Redirect(w, r, "/protected", http.StatusFound)
}

// LogoutHandler handles the logout route
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Call the Logout function in auth package
	err := auth.Logout(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusFound)
}

// ProtectedHandler handles the protected route
func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	// Call the ValidateJWT function in auth package
	valid, err := auth.ValidateJWT(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !valid {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Render the protected page
	w.Write([]byte("You have successfully logged in!"))
}

