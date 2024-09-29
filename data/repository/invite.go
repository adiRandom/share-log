package repository

import (
	"gorm.io/gorm"
	"shareLog/di"
	"shareLog/models"
)

type inviteRepository struct {
	baseRepository[models.Invite]
}

type InviteRepository interface {
	BaseRepository[models.Invite]
	GetByIdWithKeys(id uint) (*models.Invite, error)
}

type InviteRepositoryProvider struct {
}

func (k InviteRepositoryProvider) Provide() any {
	db := di.Get[*gorm.DB]()
	return &inviteRepository{
		baseRepository: newBaseRepository[models.Invite](db),
	}
}

func (r *inviteRepository) GetByIdWithKeys(id uint) (*models.Invite, error) {
	var invite models.Invite
	err := r.getDb().Preload("Keys").First(&invite, id).Error

	if err != nil {
		return nil, err
	} else {
		return &invite, err
	}
}
