package repository

import (
	"gorm.io/gorm"
	"shareLog/di"
	"shareLog/models"
)

type apiKeyRepository struct {
	baseRepository[models.ApiKey]
}

type ApiKeyRepository interface {
	BaseRepository[models.ApiKey]
	GetByKey(key string) *models.ApiKey
}

type ApiKeyRepositoryProvider struct {
}

func (a ApiKeyRepositoryProvider) Provide() any {
	var db = di.Get[*gorm.DB]()
	var instance ApiKeyRepository = &apiKeyRepository{baseRepository: newBaseRepository[models.ApiKey](db)}
	return instance
}

func (a *apiKeyRepository) GetByKey(key string) *models.ApiKey {
	var model models.ApiKey
	err := a.db.Preload("EncryptionKey").Where(models.ApiKey{
		Key: key,
	}).First(&model).Error

	if err != nil {
		return nil
	} else {
		return &model
	}
}
