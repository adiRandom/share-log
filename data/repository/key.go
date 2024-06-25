package repository

import (
	"gorm.io/gorm"
	"shareLog/di"
	"shareLog/models/encryption"
)

type keyRepository struct {
	baseRepository[encryption.EncryptionKey]
}

type KeyRepository interface {
	BaseRepository[encryption.EncryptionKey]
	GetFirstKey() (*encryption.EncryptionKey, error)
}

type KeyRepositoryProvider struct {
}

func (k KeyRepositoryProvider) Provide() KeyRepository {
	db := di.Get[*gorm.DB]()
	return &keyRepository{
		baseRepository: newBaseRepository[encryption.EncryptionKey](db),
	}
}

// FOR TESTING PURPOSES
func (r *keyRepository) GetFirstKey() (*encryption.EncryptionKey, error) {
	var key encryption.EncryptionKey
	err := r.db.First(&key).Error
	return &key, err
}
