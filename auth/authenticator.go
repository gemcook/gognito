package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var noVerificationWorningMessage = "JWT Token is not verified properly. Because you are running in 'NoVerification MODE'."

// Authenticator はユーザー認証サービスです
type Authenticator interface {
	ValidateToken(token string) (*jwt.Token, error)
}

// Auth はユーザー認証サービスです
type Auth struct {
	idp    IdentityProvider
	jwk    map[string]JWKKey
	option *Option
}

// Option defines Auth options
type Option struct {
	NoVerification bool
}

// New initializes Cognito UserPool authenticator
func New(idp IdentityProvider, opt *Option) (Authenticator, error) {

	s := &Auth{
		option: opt,
		idp:    idp,
	}

	if opt.NoVerification {
		log.Println(noVerificationWorningMessage)
		s.jwk = make(map[string]JWKKey)
		return s, nil
	}

	var jwk map[string]JWKKey

	// 1. Download and store the JSON Web Key (JWK) for your user pool.
	jwk, err := idp.JWK()

	if err != nil {
		// NetworkError or UserPool doesn't exist
		return nil, err
	}

	s.jwk = jwk
	return s, nil
}

// ValidateToken はCognitoUserPoolのJWTを検証します
func (a *Auth) ValidateToken(tokenStr string) (*jwt.Token, error) {
	token, err := validateToken(tokenStr, a.jwk, func(claims jwt.Claims) error {
		if mapClaims, ok := claims.(jwt.MapClaims); ok {
			return validateAWSJwtClaims(mapClaims, a.idp)
		}
		return fmt.Errorf("jwt claims type does not match. expected jwt.MapClaims")
	})

	// ignore the JWT validation result with NoVerification Mode.
	if a.option.NoVerification {
		log.Println(noVerificationWorningMessage)
		return token, nil
	}
	return token, err
}

func validateToken(tokenStr string, jwk map[string]JWKKey, validateClaims func(claims jwt.Claims) error) (*jwt.Token, error) {

	// 2. Decode the token string into JWT format.
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {

		// cognito user pool, googleは : RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// 5. Get the kid from the JWT token header and retrieve the corresponding JSON Web Key that was stored
		kid, ok := token.Header["kid"]
		if ok {
			if kidStr, ok := kid.(string); ok {
				key := jwk[kidStr]
				// 6. Verify the signature of the decoded JWT token.
				rsaPublicKey, err := convertKey(key.E, key.N)
				if err != nil {
					return nil, err
				}
				return rsaPublicKey, nil
			}
		}

		// rsa public key取得できず
		return nil, fmt.Errorf("no JSON Web Key matched for kid: %v", kid)
	})

	if err != nil {
		return token, err
	}

	claims := token.Claims.(jwt.MapClaims)

	err = validateClaims(claims)
	if err != nil {
		return token, err
	}

	return token, nil
}

// validateAWSJwtClaims validates AWS Cognito User Pool JWT
func validateAWSJwtClaims(claims jwt.MapClaims, userPool IdentityProvider) error {
	var err error
	// 3. Check the iss claim. It should match your user pool.
	issShouldBe := userPool.Issuer()
	err = validateClaimItem("iss", []string{issShouldBe}, claims)
	if err != nil {
		return err
	}

	// Optional. Check the aud claim. It should match client app id.
	audShouldBe := userPool.Audience()
	if audShouldBe != "" {
		err = validateClaimItem("aud", []string{audShouldBe}, claims)
		if err != nil {
			return err
		}
	}

	// 4. Check the token_use claim.
	err = validateClaimItem("token_use", []string{"id"}, claims)
	if err != nil {
		return err
	}

	// 7. Check the exp claim and make sure the token is not expired.
	err = validateExpired(claims)
	if err != nil {
		return err
	}

	return nil
}

func validateClaimItem(key string, keyShouldBe []string, claims jwt.MapClaims) error {
	if val, ok := claims[key]; ok {
		if valStr, ok := val.(string); ok {
			for _, shouldBe := range keyShouldBe {
				if valStr == shouldBe {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("%v does not match any of valid values: %v", key, keyShouldBe)
}

func validateExpired(claims jwt.MapClaims) error {
	if tokenExp, ok := claims["exp"]; ok {
		if exp, ok := tokenExp.(float64); ok {
			now := time.Now().Unix()
			fmt.Printf("current unixtime : %v\n", now)
			fmt.Printf("expire unixtime  : %v\n", int64(exp))
			if int64(exp) > now {
				return nil
			}
		}
		return fmt.Errorf("cannot parse token exp")
	}
	return fmt.Errorf("token is expired")
}

func convertKey(rawE, rawN string) (*rsa.PublicKey, error) {
	decodedE, err := base64.RawURLEncoding.DecodeString(rawE)
	if err != nil {
		return nil, err
	}
	if len(decodedE) < 4 {
		nData := make([]byte, 4)
		copy(nData[4-len(decodedE):], decodedE)
		decodedE = nData
	}
	pubKey := &rsa.PublicKey{
		N: &big.Int{},
		E: int(binary.BigEndian.Uint32(decodedE[:])),
	}
	decodedN, err := base64.RawURLEncoding.DecodeString(rawN)
	if err != nil {
		return nil, err
	}
	pubKey.N.SetBytes(decodedN)
	return pubKey, nil
}
