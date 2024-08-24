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
}

type InviteRepositoryProvider struct {
}

func (k InviteRepositoryProvider) Provide() any {
	db := di.Get[*gorm.DB]()
	return &inviteRepository{
		baseRepository: newBaseRepository[models.Invite](db),
	}
}
