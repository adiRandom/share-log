package repository

import (
	"gorm.io/gorm"
	"shareLog/di"
	"shareLog/models"
)

type keyRepository struct {
	baseRepository[models.EncryptionKey]
}

type KeyRepository interface {
	BaseRepository[models.EncryptionKey]
	GetFirstKey() (*models.EncryptionKey, error)
}

type KeyRepositoryProvider struct {
}

func (k KeyRepositoryProvider) Provide() KeyRepository {
	db := di.Get[*gorm.DB]()
	return &keyRepository{
		baseRepository: newBaseRepository[models.EncryptionKey](db),
	}
}

// FOR TESTING PURPOSES
func (r *keyRepository) GetFirstKey() (*models.EncryptionKey, error) {
	var key models.EncryptionKey
	err := r.db.First(&key).Error
	return &key, err
}
