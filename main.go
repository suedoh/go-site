package main

import (
    "log"
    "net/http"
    "path/filepath"

    "github.com/suedoh/go-site/authentication"
    "github.com/suedoh/go-site/caddyconfig"
)

func main() {
    // load configs
    config, err := caddyconfig.LoadConfig("config.json")
    if err != nil {
        log.Fatalf("Error loading config: %v", err)
    }

    // setup authentication
    auth, err := authentication.New()
    if err != nil {
        log.Fatalf("Error setting up authentication: %v", err)
    }

    // setup caddy
    c := caddyconfig.New(config)
    c.Start(auth.AuthMiddleware)

    // load templates
    templates := template.Must(template.ParseGlob(filepath.Join("templates", "*.tmpl")))

    // setup routes
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        data := &authentication.TemplateData{
            CSRFToken: csrf.Token(r),
        }
        templates.ExecuteTemplate(w, "login", data)
    })
    http.HandleFunc("/login", auth.Login)
    http.HandleFunc("/logout", auth.Logout)

    // start server
    log.Printf("Server started on http://localhost:%d", config.Listen)
    log.Fatal(http.ListenAndServe(":"+config.Listen, nil))
}

