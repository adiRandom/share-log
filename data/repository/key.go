package repository

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"gorm.io/gorm"
	"os"
	"shareLog/constants"
	"shareLog/di"
	"shareLog/models/encryption"
	"shareLog/models/userGrant"
)

type keyRepository struct {
	baseRepository[encryption.Key]
}

type KeyRepository interface {
	BaseRepository[encryption.Key]
	GetPublicKey(t userGrant.Type) *encryption.Key
	GetJwePublicKey() (*rsa.PublicKey, error)
	GetJWTPubKey() (*ecdsa.PublicKey, error)
	GetJWTPrivateKey() (*ecdsa.PrivateKey, error)
}

type KeyRepositoryProvider struct {
}

func (k KeyRepositoryProvider) Provide() any {
	db := di.Get[*gorm.DB]()
	return &keyRepository{
		baseRepository: newBaseRepository[encryption.Key](db),
	}
}

func (k *keyRepository) GetPublicKey(t userGrant.Type) *encryption.Key {
	var key encryption.Key
	err := k.getDb().Where(&encryption.Key{UserGrant: t}).First(&key).Error
	if err != nil {
		println(err)
		return nil
	}
	return &key
}

func (k *keyRepository) GetJWTPubKey() (*ecdsa.PublicKey, error) {
	key, err := k.getPemPublicKey(constants.JwtPubKeyPath)

	if err != nil {
		return nil, err
	}
	castedKey := (key).(*ecdsa.PublicKey)
	return castedKey, nil
}

func (k *keyRepository) GetJWTPrivateKey() (*ecdsa.PrivateKey, error) {
	key, err := k.getPemPrivateKey(constants.JwtPkPath)

	if err != nil {
		return nil, err
	}
	castedKey := (key).(*ecdsa.PrivateKey)
	return castedKey, nil
}

func (k *keyRepository) GetJwePublicKey() (*rsa.PublicKey, error) {
	key, err := k.getPemPublicKey(constants.JwePubKeyPath)
	if err != nil {
		return nil, err
	}
	rsaKey := (key).(*rsa.PublicKey)
	return rsaKey, nil
}

func (k *keyRepository) getPemPublicKey(path string) (any, error) {
	// Read the public key file
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pemDecoded, _ := pem.Decode(keyBytes)

	key, err := x509.ParsePKIXPublicKey(pemDecoded.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (k *keyRepository) getPemPrivateKey(path string) (any, error) {
	// Read the public key file
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pemDecoded, _ := pem.Decode(keyBytes)

	key, err := x509.ParsePKCS8PrivateKey(pemDecoded.Bytes)
	if err != nil {
		// try EC format instead of PKIX format
		ecKey, err := x509.ParseECPrivateKey(pemDecoded.Bytes)
		if err != nil {
			return nil, err
		}

		return ecKey, nil
	}

	return key, nil
}
