package kprovider

import (
	"crypto/rsa"
)

type KeyProvider interface {
	LoadPublicKey(uid string, keyPair string) (*rsa.PublicKey, error)
}
