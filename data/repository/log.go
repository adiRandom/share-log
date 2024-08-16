package repository

import (
	"gorm.io/gorm"
	"shareLog/di"
	"shareLog/models"
)

type logRepository struct {
	baseRepository[models.Log]
}

type LogRepository interface {
	BaseRepository[models.Log]
}

type LogRepositoryProvider struct {
}

func (l LogRepositoryProvider) Provide() any {
	var db = di.Get[*gorm.DB]()
	var instance LogRepository = &logRepository{baseRepository: newBaseRepository[models.Log](db)}
	return instance
}
