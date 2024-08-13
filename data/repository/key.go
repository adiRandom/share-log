package repository

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	eciesgo "github.com/ecies/go/v2"
	"gorm.io/gorm"
	"os"
	"shareLog/di"
	"shareLog/models/encryption"
	"shareLog/models/encryption/keyType"
)

type keyRepository struct {
	baseRepository[encryption.Key]
}

type KeyRepository interface {
	BaseRepository[encryption.Key]
	GetPublicKey(t keyType.Type) *encryption.Key
	GetJWTVerifyKey() *ed25519.PublicKey
}

type KeyRepositoryProvider struct {
}

func (k KeyRepositoryProvider) Provide() KeyRepository {
	db := di.Get[*gorm.DB]()
	return &keyRepository{
		baseRepository: newBaseRepository[encryption.Key](db),
	}
}

func (k *keyRepository) generatePrivateKey() *eciesgo.PrivateKey {
	key, err := eciesgo.GenerateKey()
	if err != nil {
		println(err)
		return nil
	}
	return key
}

func (k *keyRepository) GetPublicKey(t keyType.Type) *encryption.Key {
	var key encryption.Key
	err := k.getDb().Where(&encryption.Key{Type: t}).First(&key).Error
	if err != nil {
		println(err)
		return nil
	}
	return &key
}

func (k *keyRepository) GetJWTVerifyKey() *ed25519.PublicKey {
	// TODO: Implement this
	path := ""
	key, err := k.getPemPublicKey(path)

	if err != nil {
		panic("Error while parsing JWT sign public key: " + err.Error())
	}
	castedKey := (*key).(ed25519.PublicKey)
	return &castedKey
}

func (k *keyRepository) getPemPublicKey(path string) (*any, error) {
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

	return &key, nil
}
