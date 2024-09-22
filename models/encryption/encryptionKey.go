package encryption

import (
	eciesgo "github.com/ecies/go/v2"
	"gorm.io/gorm"
	"shareLog/models/userGrant"
)

type KeyOwnerEntityType string

const USER_ENTITY_TYPE KeyOwnerEntityType = "user"
const INVITE_ENTITY_TYPE KeyOwnerEntityType = "invite"

type Key struct {
	gorm.Model
	OwnerId    uint
	OwnerType  KeyOwnerEntityType
	PublicKey  *PublicKey
	PrivateKey *PrivateKey `gorm:"embedded;embeddedPrefix:pk_"`
	UserGrant  userGrant.Type
}

func NewEncryptionKey(pubKey *eciesgo.PublicKey, pkEncryptedHex string, pkIv string, t userGrant.Type) Key {
	return Key{
		PublicKey:  &PublicKey{pubKey},
		PrivateKey: &PrivateKey{EncryptedHex: pkEncryptedHex, Iv: pkIv},
		UserGrant:  t,
	}
}
