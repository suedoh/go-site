package caddyconfig

import "github.com/caddyserver/caddy/v2"

type Config struct {
    ListenAddress string
    Root         string
    Middlewares  []caddy.Middleware
    Plugins      []caddy.Plugin
}

