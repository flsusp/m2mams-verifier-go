package kprovider

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/spf13/afero"
	"io/ioutil"
)

type LocalFileSystemKProvider struct {
	FileSystem afero.Fs
	Path string
}

func NewLocalFileSystemKProvider(path string) KeyProvider {
	return LocalFileSystemKProvider{
		FileSystem: afero.NewOsFs(),
		Path: path,
	}
}

func (w LocalFileSystemKProvider) LoadPublicKey(uid string, keyPair string) (*rsa.PublicKey, error) {
	publicKeyFilePath := fmt.Sprintf("%s/%s/%s.pub.pem", w.Path, uid, keyPair)

	file, err := w.FileSystem.Open(publicKeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to load public key from file %s: %s", publicKeyFilePath, err.Error())
	}
	defer file.Close()

	keyData, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("unable to load public key from file %s: %s", publicKeyFilePath, err.Error())
	}

	key, err := ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return nil, fmt.Errorf("invalid PEM encoded public key on file %s: %s", publicKeyFilePath, err.Error())
	}
	return key, nil
}

var (
	ErrKeyMustBePEMEncoded = errors.New("invalid key: key must be PEM encoded PKCS1 or PKCS8 private key")
	ErrNotRSAPublicKey     = errors.New("key is not a valid RSA public key")
)

func ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, ErrNotRSAPublicKey
	}

	return pkey, nil
}