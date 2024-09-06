package repository

import (
	"gorm.io/gorm"
	"shareLog/di"
	"shareLog/models"
)

type userRepository struct {
	baseRepository[models.User]
}

func (u *userRepository) GetByIdWithPrivateKey(id uint) *models.User {
	var user models.User
	u.getDb().Model(&models.User{}).Preload("EncryptionKey").First(&user, id)
	return &user
}

type UserRepository interface {
	BaseRepository[models.User]
	GetByIdWithPrivateKey(id uint) *models.User
	GetByEmail(email string) (*models.User, error)
}

type UserRepositoryProvider struct {
}

func (u UserRepositoryProvider) Provide() any {
	db := di.Get[*gorm.DB]()
	return &userRepository{baseRepository: newBaseRepository[models.User](db)}
}

func (u *userRepository) GetByEmail(email string) (*models.User, error) {
	var user models.User
	err := u.getDb().Where("email = ?", email).First(&user).Error
	return &user, err
}
