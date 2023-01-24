package authentication

// A User represents a basic user of the system
type User struct {
    ID       int    `json:"id"`
    Username string `json:"username"`
    Password []byte `json:"password"`
}

