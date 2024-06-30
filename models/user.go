package models

import (
	"gorm.io/gorm"
	"shareLog/models/encryption"
)

type User struct {
	gorm.Model
	Email             string
	PasswordHash      string
	PasswordSalt      string
	EncryptionKeySalt string
	EncryptionKey     *encryption.EncryptionKey
}
