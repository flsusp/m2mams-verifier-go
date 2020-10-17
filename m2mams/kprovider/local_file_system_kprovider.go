package kprovider

import (
	"crypto/rsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
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

	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return nil, fmt.Errorf("invalid PEM encoded public key on file %s: %s", publicKeyFilePath, err.Error())
	}
	return key, nil
}
