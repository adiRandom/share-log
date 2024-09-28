package models

import (
	"gorm.io/gorm"
	"shareLog/lib"
	"shareLog/models/encryption"
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
	EncryptionKeys    []encryption.Key `gorm:"foreignKey:OwnerId"`
}

func (u *User) GetSymmetricKey() encryption.Key {
	return *lib.Find(u.EncryptionKeys, func(key encryption.Key) bool {
		return key.SymmetricKey != nil
	})
}
