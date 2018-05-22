package userpool

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gemcook/gognito"
)

// UserPooler has CognitoUserPool JWT auth info.
type UserPooler interface {
	GetJWK() (map[string]JWKKey, error)
	GetURL() string
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

// GetJWKURL returns Cognito UserPool's JWK URL.
func (up *UserPool) GetJWKURL() string {
	return fmt.Sprintf("%v/.well-known/jwks.json", up.GetURL())
}

// GetURL returns Cognito UserPool's URL.
func (up *UserPool) GetURL() string {
	return fmt.Sprintf("https://cognito-idp.%v.amazonaws.com/%v", up.Region, up.PoolID)
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

// GetJWK gets CognitoUserPool's JWK
func (up *UserPool) GetJWK() (map[string]JWKKey, error) {

	jwk := &JWK{}
	jwkURL := up.GetJWKURL()
	err := getJSON(jwkURL, jwk)
	if err != nil {
		return nil, err
	}

	jwkMap := make(map[string]JWKKey, 0)
	for _, jwk := range jwk.Keys {
		jwkMap[jwk.Kid] = jwk
	}
	return jwkMap, nil
}
