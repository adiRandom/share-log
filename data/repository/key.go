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
	GetPublicKeyForDataOwner() *encryption.EncryptionKey
}

type KeyRepositoryProvider struct {
}

func (k KeyRepositoryProvider) Provide() KeyRepository {
	db := di.Get[*gorm.DB]()
	return &keyRepository{
		baseRepository: newBaseRepository[encryption.EncryptionKey](db),
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
