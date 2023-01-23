package authentication

import (
	"net/http"
	"net/http/httptest"
	"testing"
    "time"

    "github.com/golang-jwt/jwt"
)

// TestLogin posts to /login with a fake user
func TestLogin(t *testing.T) {
	// create a request to pass to our handler
	r, _ := http.NewRequest("POST", "/login", nil)

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response
	rr := httptest.NewRecorder()

	// create a fake user
	users["testuser"] = &User{
		Username: "testuser",
		Password: "$2a$10$D4qJlHZa7w3a2eJ8YVyLmeGcJ7VzfRk9X/1fZ0bT/JwTlG6/8H6Uy",
	}

	// create the login form data
	r.PostForm = make(map[string][]string)
	r.PostForm.Add("username", "testuser")
	r.PostForm.Add("password", "password")

	// call the login handler
	Login(rr, r)

	// check the status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// check if the JWT token cookie is set
	cookie, err := rr.Result().Cookies()
	if err != nil {
		t.Errorf("Error getting cookies: %v", err)
	}
	if len(cookie) != 1 {
		t.Errorf("Expected 1 cookie, got %v", len(cookie))
	}
	if cookie[0].Name != "jwt" {
		t.Errorf("Expected JWT cookie, got %v", cookie[0].Name)
	}

	// delete the fake user
	delete(users, "testuser")
}

// TestValidate creates a fake JWT token, attaches it to a request as a cookie,
// and then calls the ValidateJWT middleware. 
// The test checks if the middleware returns the correct status code and response body.
func TestValidateJWT(t *testing.T) {
	// create a request
	r, _ := http.NewRequest("GET", "/", nil)

	// create a fake JWT token
	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = "testuser"
	claims["exp"] = time.Now().Add(time.Minute * 1).Unix()
	tokenString, _ := token.SignedString(privateKey)

	// create a JWT token cookie
	cookie := &http.Cookie{
		Name:  "jwt",
		Value: tokenString,
		Path:  "/",
	}
	r.AddCookie(cookie)

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response
	rr := httptest.NewRecorder()

	// call the ValidateJWT middleware
	ValidateJWT(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test"))
	})).ServeHTTP(rr, r)

	// check the status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// check the response body
	expected := "test"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

// TestAuthMiddleware creates a fake JWT token, attaches it to a request as a cookie, 
// and then calls the AuthMiddleware middleware. 
// The test checks if the middleware returns the correct status code and response body.
func TestAuthMiddleware(t *testing.T) {
	// create a request
	r, _ := http.NewRequest("GET", "/", nil)

	// create a fake JWT token
	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = "testuser"
	claims["exp"] = time.Now().Add(time.Minute * 1).Unix()
	tokenString, _ := token.SignedString(privateKey)

	// create a JWT token cookie
	cookie := &http.Cookie{
		Name:  "jwt",
		Value: tokenString,
		Path:  "/",
	}
	r.AddCookie(cookie)

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response
	rr := httptest.NewRecorder()

	// call the AuthMiddleware middleware
	AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test"))
	})).ServeHTTP(rr, r)

	// check the status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// check the response body
	expected := "test"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}


// function creates a fake JWT token, attaches it to a request as a cookie, 
// and then calls the Logout handler. The test checks if the handler returns 
// the correct status code and if the JWT token cookie is deleted.
func TestLogout(t *testing.T) {
	// create a request
	r, _ := http.NewRequest("GET", "/logout", nil)

	// create a fake JWT token
	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = "testuser"
	claims["exp"] = time.Now().Add(time.Minute * 1).Unix()
	tokenString, _ := token.SignedString(privateKey)

	// create a JWT token cookie
	cookie := &http.Cookie{
		Name:  "jwt",
		Value: tokenString,
		Path:  "/",
	}
	r.AddCookie(cookie)

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response
	rr := httptest.NewRecorder()

	// call the Logout handler
	Logout(rr, r)

	// check the status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// check if the JWT token cookie is deleted
	cookie, err := rr.Result().Cookies()
	if err != nil {
		t.Errorf("Error getting cookies: %v", err)
	}
	if len(cookie) != 0 {
		t.Errorf("Expected no cookies, got %v", len(cookie))
	}
}

func TestGenerateJWT(t *testing.T) {
	// create a user
	user := &User{
		Username: "testuser",
		Password: "testpassword",
	}

	// create a token
	token, err := GenerateJWT(user)
	if err != nil {
		t.Errorf("Error generating token: %v", err)
	}

	// check if the token is valid
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Errorf("Error parsing token: %v", err)
	}

	if !parsedToken.Valid {
		t.Errorf("Expected token to be valid, got invalid")
	}
}

