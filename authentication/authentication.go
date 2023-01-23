package authentication

/*
Package authentication implements the authentication process for a web application.

It includes functions for:
- Login: Handles the login process. It retrieves the form data, checks if the user exists, and if the password is correct, it creates a new JWT token and stores it in a cookie.
- ValidateJWT: Validates the JWT token. It retrieves the JWT token from the cookie, parses the token, and checks if it is valid.
- AuthMiddleware: Is a middleware that checks if the user is authenticated. It calls the ValidateJWT function to check if the user is authenticated, if the user is not authenticated it returns an unauthorized error message.
- Logout: Handles the logout process. It deletes the JWT token cookie by setting its value to an empty string and its expiration date to the current time.

Please note that in this example, the public key is hardcoded in the code, this is not a good practice, it should be read from a file and kept in a secure location.
Also, the JWT token is stored in a cookie, it would be recommended to store the JWT token in an HttpOnly and Secure cookie for better security.
*/


import (
    "fmt"
    "time"
    "net/http"

    "github.com/dgrijalva/jwt-go"
    "golang.org/x/crypto/bcrypt"
)

const (
    privKeyPath = "app.rsa"
    pubKeyPath  = "app.rsa.pub"
)

// hardcoded password for now while getting off the ground
// TODO: use env variable for password
var (
    signingKey, _ = jwt.ParseRSAPrivateKeyFromPEM([]byte(privKeyPath))
    verifyKey, _ = jwt.ParseRSAPublicKeyFromPEM([]byte(pubKeyPath))
    users = map[string]User{
        "testuser": {
            Username: "testuser",
            Password: "$2y$10$XV2/N6/5gB1L/Zw5VxmJIuDQj9zrKZm7Vu8WgjK7G/p.bqw3/f8W.",
        },
    }
)

// Login handles the login process
// Login handles the login process
func Login(w http.ResponseWriter, r *http.Request) (bool, error) {
    if r.Method == http.MethodPost {
        // parse the form data
        err := r.ParseForm()
        if err != nil {
            return false, fmt.Errorf("Error parsing form data: %v", err)
        }

        // retrieve the form data
        username := r.Form.Get("username")
        password := r.Form.Get("password")

        // check if the user exists
        user, ok := users[username]
        if !ok {
            return false, fmt.Errorf("User not found")
        }

        // Compare the stored hashed password with the one the user entered
        err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
        if err != nil {
            return false, fmt.Errorf("Invalid password")
        }

        // create a new JWT token
        token := jwt.New(jwt.SigningMethodRS256)

        // set the claims
        claims := token.Claims.(jwt.MapClaims)
        claims["username"] = user.Username
        claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

        // Sign and get the complete encoded token as a string
        tokenString, err := token.SignedString(signingKey)
        if err != nil {
            return false, fmt.Errorf("Error signing token: %v", err)
        }

        // set the token as a cookie
        http.SetCookie(w, &http.Cookie{
            Name:    "jwt",
            Value:   tokenString,
            Expires: time.Now().Add(time.Hour * 24),
            HttpOnly: true,
            Secure: true,
        })
        return true, nil
    }
    return false, nil
}

// ValidateJWT validates the JWT token
func ValidateJWT(r *http.Request) (bool, error) {
    // retrieve the JWT token from the cookie
    cookie, err := r.Cookie("jwt")
    if err != nil {
        return false, fmt.Errorf("Error retrieving cookie: %v", err)
    }

    // parse the JWT token
    token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
        }
        return verifyKey, nil
    })

    // check if the JWT token is valid
    if err != nil {
        return false, fmt.Errorf("Error parsing token: %v", err)
    }
    if !token.Valid {
        return false, fmt.Errorf("Invalid token")
    }
    return true, nil
}

// AuthMiddleware is a middleware that checks if the user is authenticated
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        isAuth, err := ValidateJWT(r)
        if err != nil {
            http.Error(w, err.Error(), http.StatusUnauthorized)
            return
        }
        if !isAuth {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        next.ServeHTTP(w, r)
    })
}

// Logout handles the logout process
func Logout(w http.ResponseWriter, r *http.Request) {
    // delete the JWT token cookie
    http.SetCookie(w, &http.Cookie{
        Name:    "jwt",
        Value:   "",
        Expires: time.Now(),
    })
}

