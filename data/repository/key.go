package repository

import (
	eciesgo "github.com/ecies/go/v2"
	"gorm.io/gorm"
	"shareLog/di"
	"shareLog/models/encryption"
)

type keyRepository struct {
	baseRepository[encryption.EncryptionKey]
}

func (k *keyRepository) GetPublicKeyForDataOwner() *encryption.EncryptionKey {
	var key encryption.EncryptionKey
	err := k.getDb().Where(&encryption.EncryptionKey{Type: encryption.OWNER_PUBLIC_KEY}).First(&key).Error
	if err != nil {
		println(err)
		return nil
	}
	return &key
}

type KeyRepository interface {
	BaseRepository[encryption.EncryptionKey]
	Create(keyType string) *encryption.EncryptionKey
	GetPublicKeyForDataOwner() *encryption.EncryptionKey
	GetFirst(keyType string) *encryption.EncryptionKey
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
