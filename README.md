# gognito

gognito provides the way to verify Cognito UserPool's JSON Web Token and handle the claims.

## Installation

```sh
go get "github.com/gemcook/gognito"
```

If you use `dep`

```sh
dep ensure -add "github.com/gemcook/gognito"
```

## Example

```go
package main

import (
    "os"
    "log"
    "github.com/gemcook/gognito/auth"
)

func main(){

    // Set Cognito UserPool information
    authenticator, err := auth.New(
        &auth.UserPool{
            Region: os.Getenv("COGNITO_REGION"),
            PoolID: os.Getenv("COGNITO_USER_POOL_ID"),
        },
        &auth.Option{
            // [!important]
            // If NoVerification option is set true, authenticator accepts NOT VALID JWT.
            // That means authenticator ignores "wrong signature", "expired", "wrong issuer", and so on.
            // Use this feature only for development environment.
            NoVerification: false,
        })

    token := "eyJraW...."

    // verify the token is valid.
    jwt, err := authenticator.ValidateToken(token)
    if err != nil {
        log.Fatal("something wrong with the token")
    }

    // ...
}
```
