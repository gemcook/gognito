package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gemcook/gognito"
)

// IdentityProvider provides the information to authenticate user.
type IdentityProvider interface {
	JWK() (map[string]JWKKey, error)
	Issuer() string
	Audience() string
}

// JWK is json data struct for JSON Web Key.
type JWK struct {
	Keys []JWKKey
}

// JWKKey is json data struct for cognito jwk key.
type JWKKey struct {
	Alg string
	E   string
	Kid string
	Kty string
	N   string
	Use string
}

// UserPool has CognitoUserPool JWT auth info.
type UserPool struct {
	gognito.UserPool
}

// URL returns Cognito UserPool's URL.
func (up *UserPool) URL() string {
	return fmt.Sprintf("https://cognito-idp.%v.amazonaws.com/%v", up.Region, up.PoolID)
}

// JWKURL returns Cognito UserPool's JWK URL.
func (up *UserPool) JWKURL() string {
	return fmt.Sprintf("%v/.well-known/jwks.json", up.URL())
}

// Issuer returns iss for JWT claims
func (up *UserPool) Issuer() string {
	return up.URL()
}

// Audience returns aud for JWT claims
func (up *UserPool) Audience() string {
	return up.AppClientID
}

// getJSON downloads JSON data from the given url, then apply to target.
func getJSON(url string, target interface{}) error {
	var myClient = &http.Client{Timeout: 10 * time.Second}
	r, err := myClient.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	return json.NewDecoder(r.Body).Decode(target)
}

// JWK gets CognitoUserPool's JWK
func (up *UserPool) JWK() (map[string]JWKKey, error) {

	jwk := &JWK{}
	jwkURL := up.JWKURL()
	err := getJSON(jwkURL, jwk)
	if err != nil {
		return nil, err
	}

	jwkMap := make(map[string]JWKKey, 0)
	for _, key := range jwk.Keys {
		jwkMap[key.Kid] = key
	}
	return jwkMap, nil
}
