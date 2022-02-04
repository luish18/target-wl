module github.com/luish18/target-wl

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/marco-developer/dasvid/poclib v1.0.0
	github.com/spiffe/go-spiffe/v2 v2.0.0-beta.11 // indirect
)

replace github.com/marco-developer/dasvid/poclib v1.0.0 => ./poclib

go 1.16
