package repository

import (
	"fmt"
	"gorm.io/gorm"
	"shareLog/di"
	"shareLog/models"
)

type logRepository struct {
	baseRepository[models.Log]
}

type LogRepository interface {
	BaseRepository[models.Log]
	GetByRefId(logId uint) *models.Log
}

type LogRepositoryProvider struct {
}

func (l LogRepositoryProvider) Provide() any {
	var db = di.Get[*gorm.DB]()
	var instance LogRepository = &logRepository{baseRepository: newBaseRepository[models.Log](db)}
	return instance
}

func (r *baseRepository[T]) GetByRefId(logId uint) *T {
	db := r.getDb()
	var result T
	err := db.First(&result, models.Log{
		RefLogId: logId,
	}).Error

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return &result
}
