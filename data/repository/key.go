package repository

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"gorm.io/gorm"
	"os"
	"shareLog/config"
	"shareLog/di"
	"shareLog/models/encryption"
	"shareLog/models/userGrant"
)

type keyRepository struct {
	baseRepository[encryption.Key]
}

type KeyRepository interface {
	BaseRepository[encryption.Key]
	GetPublicKey(t userGrant.Type) *encryption.PublicKey
	GetJwePublicKey() (*rsa.PublicKey, error)
	GetJWTPubKey() (*ecdsa.PublicKey, error)
	GetJWTPrivateKey() (*ecdsa.PrivateKey, error)
	GetJWEPrivateKey() (*rsa.PrivateKey, error)
	GetUnacquiredSharedKey(userId uint, logId uint) (*encryption.Key, error)
	GetUnacquiredSharedKeys(userId uint) ([]encryption.Key, error)
	GetAcquiredSharedKeyForLogId(userId, logId uint) (*encryption.Key, error)
}

type KeyRepositoryProvider struct {
}

func (k KeyRepositoryProvider) Provide() any {
	db := di.Get[*gorm.DB]()
	return &keyRepository{
		baseRepository: newBaseRepository[encryption.Key](db),
	}
}

func (k *keyRepository) GetPublicKey(t userGrant.Type) *encryption.PublicKey {
	var key encryption.Key
	err := k.getDb().Where(&encryption.Key{UserGrant: t}).First(&key).Error
	if err != nil {
		println(err)
		return nil
	}
	return key.PublicKey
}

func (k *keyRepository) GetJWTPubKey() (*ecdsa.PublicKey, error) {
	key, err := k.getPemPublicKey(config.GetKeyPaths().JwtPubKeyPath)

	if err != nil {
		return nil, err
	}
	castedKey := (key).(*ecdsa.PublicKey)
	return castedKey, nil
}

func (k *keyRepository) GetJWTPrivateKey() (*ecdsa.PrivateKey, error) {
	key, err := k.getPemPrivateKey(config.GetKeyPaths().JwtPkPath)

	if err != nil {
		return nil, err
	}
	castedKey := (key).(*ecdsa.PrivateKey)
	return castedKey, nil
}
func (k *keyRepository) GetJWEPrivateKey() (*rsa.PrivateKey, error) {
	key, err := k.getPemPrivateKey(config.GetKeyPaths().JwePkPath)

	if err != nil {
		return nil, err
	}
	castedKey := (key).(*rsa.PrivateKey)
	return castedKey, nil
}

func (k *keyRepository) GetJwePublicKey() (*rsa.PublicKey, error) {
	key, err := k.getPemPublicKey(config.GetKeyPaths().JwePubKeyPath)
	if err != nil {
		return nil, err
	}
	rsaKey := (key).(*rsa.PublicKey)
	return rsaKey, nil
}

func (k *keyRepository) getPemPublicKey(path string) (any, error) {
	// Read the public key file
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pemDecoded, _ := pem.Decode(keyBytes)

	key, err := x509.ParsePKIXPublicKey(pemDecoded.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (k *keyRepository) getPemPrivateKey(path string) (any, error) {
	// Read the public key file
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pemDecoded, _ := pem.Decode(keyBytes)

	key, err := x509.ParsePKCS8PrivateKey(pemDecoded.Bytes)
	if err != nil {
		// try EC format instead of PKIX format
		ecKey, err := x509.ParseECPrivateKey(pemDecoded.Bytes)
		if err != nil {
			return nil, err
		}

		return ecKey, nil
	}

	return key, nil
}

func (k *keyRepository) GetUnacquiredSharedKeys(userId uint) ([]encryption.Key, error) {
	var keys []encryption.Key

	subquery := k.db.Model(&encryption.Key{}).
		// If we find a key already acquired for this log and user
		// the not in the main query will return false (!"1" -> false)
		// But if there aren't any results here, we'll have !$empty$ -> true
		Select("1").
		Where("log_id = main.log_id").
		Where("user_owner_id = ?", userId)

	err := k.db.
		Table("keys as main").
		Where("user_owner_id IS NULL").
		Where(encryption.Key{
			UserGrant: userGrant.Types.GrantShared,
		}).
		Where("NOT EXISTS (?)", subquery).
		Find(&keys).Error

	return keys, err
}

func (k *keyRepository) GetUnacquiredSharedKey(userId uint, logId uint) (*encryption.Key, error) {
	var key encryption.Key

	subquery := k.db.Model(&encryption.Key{}).
		// If we find a key already acquired for this log and user
		// the not in the main query will return false (!"1" -> false)
		// But if there aren't any results here, we'll have !$empty$ -> true
		Select("1").
		Where("log_id = ?", logId).
		Where("user_owner_id = ?", userId)

	err := k.db.
		Table("keys as main").
		Where("user_owner_id IS NULL").
		Where(encryption.Key{
			LogId:     &logId,
			UserGrant: userGrant.Types.GrantShared,
		}).
		Where("NOT EXISTS (?)", subquery).
		First(&key).Error

	if err != nil {
		return nil, err
	}

	return &key, nil
}

func (k *keyRepository) GetAcquiredSharedKeyForLogId(userId, logId uint) (*encryption.Key, error) {
	var key encryption.Key
	err := k.db.Model(&encryption.Key{}).Where(encryption.Key{
		LogId:       &logId,
		UserOwnerId: &userId,
	}).First(&key).Error

	return &key, err
}
