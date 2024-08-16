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
	"shareLog/models/userGrant"
)

type keyRepository struct {
	baseRepository[encryption.Key]
}

type KeyRepository interface {
	BaseRepository[encryption.Key]
	GetPublicKey(t userGrant.Type) *encryption.Key
	GetJWTVerifyKey() *ed25519.PublicKey
	CreateDefaultKeys()
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

// Test code

func (k *keyRepository) CreateDefaultKeys() {
	var keyCount int64
	if k.db.Model(&encryption.Key{}).Where("id = 1000").First(&encryption.Key{}).Count(&keyCount); keyCount > 0 {
		return
	}

	key, _ := eciesgo.GenerateKey()
	pk, _ := encryption.NewPrivateKeyFromHex(key.Hex())

	keyModel := encryption.Key{
		Model: gorm.Model{
			ID: 1000,
		},
		UserGrant: userGrant.GRANT_OWNER,
		PublicKey: &encryption.PublicKey{
			Key: key.PublicKey,
		},
		PrivateKey: pk,
	}

	k.db.Create(&keyModel)
}
