package repository

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	eciesgo "github.com/ecies/go/v2"
	"gorm.io/gorm"
	"os"
	"shareLog/constants"
	"shareLog/di"
	"shareLog/models/encryption"
)

type keyRepository struct {
	baseRepository[encryption.EncryptionKey]
}

type KeyRepository interface {
	BaseRepository[encryption.EncryptionKey]
	Create(keyType string) *encryption.EncryptionKey
	// GetSharedDataOwnerPublicKey returns the public key used to encrypt logs at the owner level
	GetSharedDataOwnerPublicKey() *encryption.EncryptionKey
	GetFirst(keyType string) *encryption.EncryptionKey
	GetJWTVerifyKey() *ed25519.PublicKey
	GetJWEDecryptKey() *ecdsa.PrivateKey
}

type KeyRepositoryProvider struct {
}

func (k KeyRepositoryProvider) Provide() KeyRepository {
	db := di.Get[*gorm.DB]()
	return &keyRepository{
		baseRepository: newBaseRepository[encryption.EncryptionKey](db),
	}
}

func (k *keyRepository) Create(keyType string) *encryption.EncryptionKey {
	key := k.generatePrivateKey()
	if key == nil {
		return nil
	}
	encryptionKey := encryption.NewEncryptionKey(*key, keyType)
	err := k.getDb().Create(&encryptionKey).Error
	if err != nil {
		println(err)
		return nil
	}
	return &encryptionKey
}

// Testing code
func (k *keyRepository) GetFirst(keyType string) *encryption.EncryptionKey {
	var key encryption.EncryptionKey
	err := k.getDb().Where(&encryption.EncryptionKey{Type: keyType}).First(&key).Error
	if err != nil {
		println(err)
		return nil
	}
	return &key
}

func (k *keyRepository) generatePrivateKey() *eciesgo.PrivateKey {
	key, err := eciesgo.GenerateKey()
	if err != nil {
		println(err)
		return nil
	}
	return key
}

func (k *keyRepository) GetSharedDataOwnerPublicKey() *encryption.EncryptionKey {
	var key encryption.EncryptionKey
	err := k.getDb().Where(&encryption.EncryptionKey{Type: encryption.OWNER_PUBLIC_KEY}).First(&key).Error
	if err != nil {
		println(err)
		return nil
	}
	return &key
}

func (k *keyRepository) GetJWTVerifyKey() *ed25519.PublicKey {
	key, err := k.getPemPublicKey(constants.JWTSignPublicKeyPath)
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

func (k *keyRepository) GetJWEDecryptKey() *ecdsa.PrivateKey {
	// Read the public key file
	keyBytes, err := os.ReadFile(constants.JWEPrivateKeyPath)
	if err != nil {
		panic("Couldn't read JWE private key")
	}

	pemDecoded, _ := pem.Decode(keyBytes)

	key, err := x509.ParsePKCS8PrivateKey(pemDecoded.Bytes)
	if err != nil {
		panic("Couldn't parse JWE private key")
	}

	castedKey := key.(ecdsa.PrivateKey)
	return &castedKey
}
