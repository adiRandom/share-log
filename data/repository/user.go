package repository

import (
	"gorm.io/gorm"
	"shareLog/di"
	"shareLog/models"
)

type userRepository struct {
	baseRepository[models.User]
}

type UserRepository interface {
	BaseRepository[models.User]
	GetByEmail(email string) (*models.User, error)
}

type UserRepositoryProvider struct {
}

func (u UserRepositoryProvider) Provide() UserRepository {
	db := di.Get[*gorm.DB]()
	return &userRepository{baseRepository: newBaseRepository[models.User](db)}
}

func (u *userRepository) GetByEmail(email string) (*models.User, error) {
	var user models.User
	err := u.getDb().Where("email = ?", email).First(&user).Error
	return &user, err
}
