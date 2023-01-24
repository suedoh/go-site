package authentication

// Claims struct holds the claims for the JWT
type Claims struct {
    UserID    int    `json:"user_id"`
    Email     string `json:"email"`
    Role      string `json:"role"`
    jwt.StandardClaims
}

func (c Claims) Valid() error {
    return c.StandardClaims.Valid()
}
