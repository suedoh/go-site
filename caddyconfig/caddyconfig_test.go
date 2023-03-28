package caddyconfig

import (
	"net/http"
    "httptest"
	"testing"

	"github.com/suedoh/go-site/authentication"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"github.com/caddyserver/caddy"
)

func TestConfigureCaddy(t *testing.T) {
	c := caddy.NewTestController("http", `
		tls self_signed
		onion
		route /login  {
			handle  {
					(authentication.Login)
			}
		}
		route /logout  {
			handle  {
					(authentication.Logout)
			}
		}
		route /private  {
			handle  {
					(authentication.AuthMiddleware)
					(handleYourPrivateRoute)
			}
		}
	`)
	err := c.Run()
	if err != nil {
		t.Fatalf("Error running caddy: %v", err)
	}
}

func TestHandleYourPrivateRoute(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/private", nil)
	status, err := handleYourPrivateRoute(w, r)
	if err != nil {
		t.Fatalf("Error handling the request: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("Expected status %d but got %d", http.StatusOK, status)
	}
}

