package verifier

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/flsusp/m2mams-verifier-go/m2mams/kprovider"
)

type Verifier struct {
	KeyProvider kprovider.KeyProvider
}

type VerificationResult struct {
	uid string
	keyPair string
}

func (v Verifier) VerifySignedToken(tk string) (*VerificationResult, error) {
	parsedToken, err := jwt.Parse(tk, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		claims := token.Claims.(jwt.MapClaims)
		uid := claims["uid"].(string)
		kp := claims["kp"].(string)

		return v.KeyProvider.LoadPublicKey(uid, kp)
	})

	if err != nil {
		return nil, err
	}

	if !parsedToken.Valid {
		return nil, errors.New("invalid token")
	}

	claims := parsedToken.Claims.(jwt.MapClaims)

	return &VerificationResult{
		uid: claims["uid"].(string),
		keyPair: claims["kp"].(string),
	}, nil
}
