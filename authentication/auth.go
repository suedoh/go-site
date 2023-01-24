package auth

import (
    "net/http"
    "time"

    "github.com/gorilla/csrf"
)

// User represents a user with a username and password
type User struct {
    Username string
    Password string
}

// Auth represents the state of a user's authentication
type Auth struct {
    Authenticated bool
    User          User
    CSRFToken     string
}

// LoginHandler handles a login request
func LoginHandler(w http.ResponseWriter, r *http.Request) {
    // Get the user from the database
    user := getUser(r.FormValue("username"), r.FormValue("password"))
    if user.Username == "" {
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    // Create a new JWT token
    token := jwt.New(jwt.SigningMethodHS256)

    // Set claims
    claims := token.Claims.(jwt.MapClaims)
    claims["username"] = user.Username
    claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

    // Generate encoded token and send it as response.
    t, err := token.SignedString([]byte("secret"))
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Create a new authentication state
    auth := Auth{
        Authenticated: true,
        User:          user,
        CSRFToken:     csrf.Token(r),
    }

    // Store the authentication state in a cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "auth",
        Value:    t,
        HttpOnly: true,
    })

    // Render the authenticated template
    renderTemplate(w, "authenticated", auth)
}

// LogoutHandler handles a logout request
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
    // Delete the auth cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "auth",
        MaxAge:   -1,
        HttpOnly: true,
    })

    // Redirect the user to the login page
    http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ValidateJWT validates a JWT token
func ValidateJWT(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        return []byte(os.Getenv("JWT_SECRET")), nil
    })

    if claims, ok := token.Claims.(*Claims); ok && token.Valid {
        return claims, nil
    } else {
        return nil, err
    }
}

