# Authentication Package

Found in Authentication package:
- A struct User that represents a user and their information (username, password, etc.)
- A function Login that handles user login by validating the provided credentials, generating a JWT token, and returning it as a cookie
- A function ValidateJWT that validates a JWT token by checking if it is signed with the correct key, and if the claims (username, expiry, etc.) are valid
- A function AuthMiddleware that is a middleware that checks if a valid JWT token is included in the request cookies, and if so, it adds the username to the request context
- A function Logout that handles user logout by deleting the JWT token cookie
- A function GenerateJWT that generates a JWT token from a user struct and sign it with a private key
- Test functions for each of the above functions.
