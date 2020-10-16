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

func (v Verifier) VerifySignedToken(tk string) error {
	parsedToken, err := jwt.Parse(tk, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		claims := token.Claims.(jwt.MapClaims)
		uid := claims["uid"].(string)
		kp := claims["kp"].(string)

		return v.KeyProvider.LoadPublicKey(uid, kp)
	})

	if err != nil {
		return err
	}

	if !parsedToken.Valid {
		return errors.New("invalid token")
	}
	return nil
}
