package models

import (
	"gorm.io/gorm"
	"shareLog/models/encryption"
)

type ApiKey struct {
	gorm.Model
	Key             string
	EncryptionKeyId uint
	// Client level encryption key to use on the app client
	EncryptionKey *encryption.Key `gorm:"foreignKey:EncryptionKeyId"`
}
