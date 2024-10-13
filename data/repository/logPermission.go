package repository

import (
	"gorm.io/gorm"
	"shareLog/di"
	"shareLog/models"
)

type logPermissionRepository struct {
	baseRepository[models.PermissionRequest]
}

type LogPermissionRepository interface {
	BaseRepository[models.PermissionRequest]
	GetByLogId(logId uint) (*models.PermissionRequest, error)
	GetAllAcquiredByUser(userId uint) ([]models.PermissionRequest, error)
	GetAllUnacquiredByUser(userId uint) ([]models.PermissionRequest, error)
}

type LogPermissionRepositoryProvider struct {
}

func (l LogPermissionRepositoryProvider) Provide() any {
	var db = di.Get[*gorm.DB]()
	var instance LogPermissionRepository = &logPermissionRepository{
		baseRepository: newBaseRepository[models.PermissionRequest](db),
	}
	return instance
}

func (l *logPermissionRepository) GetByLogId(logId uint) (*models.PermissionRequest, error) {
	var request models.PermissionRequest
	err := l.db.Where(&models.PermissionRequest{
		LogID: logId,
	}).First(&request).Error

	if err != nil {
		return nil, err
	}

	return &request, nil
}

func (l *logPermissionRepository) GetAllAcquiredByUser(userId uint) ([]models.PermissionRequest, error) {
	var requests []models.PermissionRequest
	subquery := l.db.
		Table("keys").
		Select("COUNT(*)").
		Where("user_owner_id = ? AND log_id = id", userId)

	err := l.db.Table("permission_requests").
		Where("status = ? AND (?) > 0", models.PermissionRequestStatuses.Approved.Status, subquery).
		Find(&requests).
		Error

	return requests, err
}

func (l *logPermissionRepository) GetAllUnacquiredByUser(userId uint) ([]models.PermissionRequest, error) {
	var requests []models.PermissionRequest
	subquery := l.db.
		Table("keys").
		Select("COUNT(*)").
		Where("user_owner_id = ? AND log_id = id", userId)

	err := l.db.Table("permission_requests").
		Where("status <> ? OR (?) = 0", models.PermissionRequestStatuses.Approved.Status, subquery).
		Find(&requests).
		Error

	return requests, err
}
