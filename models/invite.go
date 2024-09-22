package models

import (
	"gorm.io/gorm"
	"shareLog/lib"
	"shareLog/models/dto"
	"shareLog/models/encryption"
	"shareLog/models/userGrant"
)

type Invite struct {
	gorm.Model
	Keys     []encryption.Key `gorm:"foreignKey:OwnerId"`
	CodeHash string
	// The salt used for hashing the code and storing it in the database
	HashSalt string
	// The salt used for a temporary key from the code
	DeriveSalt string
	Grant      userGrant.Type
}

func NewInvite(keys []encryption.Key, code, deriveSalt, hashSalt string, grant userGrant.Type) (*Invite, error) {
	hashedCode, err := lib.HashPassword(code, hashSalt)
	if err != nil {
		return nil, err
	}

	return &Invite{

		Keys:     keys,
		HashSalt: hashSalt,
		CodeHash: hashedCode,
		Grant:    grant,
	}, nil
}

func (i Invite) ToDto() dto.Invite {
	return dto.Invite{
		InviteId: i.ID,
	}
}
