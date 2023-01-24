package caddyconfig

import (
    "encoding/json"

    "github.com/caddyserver/caddy/v2"
    "github.com/caddyserver/caddy/v2/modules/caddyhttp"
    "github.com/caddyserver/caddy/v2/modules/caddytls"
    "github.com/gorilla/csrf"
    "github.com/suedoh/go-site/authentication"
)

func init() {
    caddy.RegisterModule(Caddy{})
}

type Caddy struct {
    Listen      string   `json:"listen,omitempty"`
    Root        string   `json:"root,omitempty"`
    TLS         bool     `json:"tls,omitempty"`
    Certificate string   `json:"certificate,omitempty"`
    Key         string   `json:"key,omitempty"`
    Middlewares []string `json:"middlewares,omitempty"`
    Plugins     []string `json:"plugins,omitempty"`
}

// CaddyProvider sets up the caddy server config
func (c Caddy) CaddyModule() caddy.Module {
    return caddy.ModuleMap{
        "http.server": caddyhttp.ServerModuleMap,
        "tls.cert":    caddytls.CertModuleMap,
    }
}

// Provision sets up the caddy server config
func (c Caddy) Provision(ctx caddy.Context) error {
    ctx.ServerBlockKeys = append(ctx.ServerBlockKeys, c.Listen)
    return nil
}

// Validate validates the caddy config
func (c Caddy) Validate() error {
    return nil
}

// Start starts the caddy server
func Start(c *Caddy) error {
    caddy.AppName = "caddy"
    caddy.AppVersion = "0.0.1"
    caddy.Quiet = false
    caddy.SetDefaultCaddyfileLoader("default", caddy.LoaderFunc(caddyconfigParse))

    controller := caddy.NewTestController("http", c.Listen)
    caddyconfigParse(controller)
    controller.Start()

    return nil
}

func caddyconfigParse(c *caddy.Controller) error {
    c.Next() // consume the root directive
    if !c.NextArg() {
        return c.ArgErr()
    }
    root := c.Val()
    c.Next()
    for c.NextBlock() {
        switch c.Val() {
        case "tls":
            if !c.NextArg() {
                return c.ArgErr()
            }
            cert := c.Val()
            if !c.NextArg() {
                return c.ArgErr()
            }
            key := c.Val()
            c.Append("tls", cert, key)
        case "route":
            route := caddyconfig.JSON(value)
            if route == nil {
                return nil, caddyconfig.Err("route value is not valid JSON")
            }
            routeMap := route.(map[string]interface{})
            path, ok := routeMap["path"]
            if !ok {
                return nil, caddyconfig.Err("route value is missing path")
            }
            pathStr, ok := path.(string)
            if !ok {
                return nil, caddyconfig.Err("route path is not a string")
            }
            dest, ok := routeMap["dest"]
            if !ok {
                return nil, caddyconfig.Err("route value is missing dest")
            }
            destStr, ok := dest.(string)
            if !ok {
                return nil, caddyconfig.Err("route dest is not a string")
            }
            c.Routes = append(c.Routes, Route{
                Path: pathStr,
                Dest: destStr,
            })
        }
    }

    return c, nil
}

