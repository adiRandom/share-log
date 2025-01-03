package models

import (
	"gorm.io/gorm"
	"shareLog/models/encryption"
	"shareLog/models/userGrant"
)

type User struct {
	gorm.Model
	Email        string
	PasswordHash string
	PasswordSalt string
	/**
	Used to derive a the user symmetric key to encrypt/decrypt keys
	*/
	EncryptionKeySalt string
	EncryptionKeys    []encryption.Key `gorm:"foreignKey:UserOwnerId"`
	Grant             userGrant.Type
}
