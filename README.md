# OIDC Code flow example using Golang

You will need a client set up an IdP (e.g. IdentityServer) running on `https://localhost:5001`.
The client will need to be called "go_oidc" and the secret should be "foobar".
The client's allowed redirect_uri/callback should be `http://127.0.0.1:5556/callback`
The client should be allowed access to the `profile` and `openid` scopes.
Make sure the client is not configured to require PKCE.

## install and run

```
go mod tidy
go build
go run
```