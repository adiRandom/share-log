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
	CreateDefaultUser()
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

func (u *userRepository) CreateDefaultUser() {
	var userCount int64
	if u.db.Model(&models.User{}).Where("id = 1000").First(&models.User{}).Count(&userCount); userCount > 0 {
		return
	}

	user := models.User{
		Model: gorm.Model{
			ID: 1000,
		},
		Email:             "test@gmail.com",
		PasswordHash:      "test",
		PasswordSalt:      "test",
		EncryptionKeySalt: "test",
		EncryptionKeyID:   1000,
		EncryptionKey:     nil,
	}

	u.db.Create(&user)
}
