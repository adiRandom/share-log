package services

import (
	"fmt"
	jwtLib "github.com/golang-jwt/jwt/v5"
	"shareLog/config"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/lib"
	"shareLog/models"
	"shareLog/models/encryption"
	"shareLog/models/userGrant"
	"strconv"
)

type keyManager struct {
	keyRepository repository.KeyRepository
	cryptoService Crypto
}

type KeyManager interface {
	AcquireSharedKeys(user *models.User, password string, salt string) ([]encryption.Key, error)
	AcquireSharedKey(
		user *models.User,
		keyToAcquire *encryption.Key,
		userSymmetricKey string,
		saveToDb bool,
	) (*encryption.Key, error)
	EncodeUserSymmetricKeyForJWT(userSymmetricKey []byte) string
	DecodeUserSymmetricKeyForJWT(userSymmetricKey string) (string, error)
	GetKeysForInvite(
		refUser *models.User,
		refUserSymmetricKey string,
		grantType userGrant.Type,
		inviteCode string,
	) ([]encryption.Key, error)
	CreateKeysForNewUser(
		invite *models.Invite,
		code string,
		password string,
		symmetricKeySalt string,
	) ([]encryption.Key, error)
	GetUserSymmetricKey(jwt jwtLib.Token) (string, error)
}

type KeyManagerProvider struct {
}

func (m KeyManagerProvider) Provide() any {
	var instance KeyManager = &keyManager{
		keyRepository: di.Get[repository.KeyRepository](),
		cryptoService: di.Get[Crypto](),
	}
	return instance
}

func (k *keyManager) AcquireSharedKey(
	user *models.User,
	keyToAcquire *encryption.Key,
	userSymmetricKey string,
	saveToDb bool,
) (*encryption.Key, error) {
	sharedKeySymmetricKey := k.cryptoService.DeriveSecurePassphrase(config.GetSecrets().LogSharingSecret, keyToAcquire.Salt)
	pk, err := keyToAcquire.PrivateKey.Key(sharedKeySymmetricKey)
	if err != nil {
		return nil, err
	}
	acquiredKey, err := k.cryptoService.CreateEncryptionKey(pk, user.Grant, userSymmetricKey, user.EncryptionKeySalt)
	if err != nil {
		return nil, err
	}

	acquiredKey.LogId = keyToAcquire.LogId
	acquiredKey.UserOwnerId = &user.ID

	if saveToDb {
		err = k.keyRepository.Save(acquiredKey)
		if err != nil {
			return nil, err
		}
	}

	return acquiredKey, nil
}

func (k *keyManager) AcquireSharedKeys(user *models.User, password string, salt string) ([]encryption.Key, error) {
	acquiredPks := make([]encryption.Key, 0)
	userSymmetricKey := k.cryptoService.DeriveUserSymmetricKey(password, salt)

	keysToAcquire, err := k.keyRepository.GetUnacquiredSharedKeys(user.ID)
	if err != nil {
		return acquiredPks, err
	}

	for _, keyToAcquire := range keysToAcquire {
		acquiredKey, err := k.AcquireSharedKey(user, &keyToAcquire, userSymmetricKey, false)
		if err != nil {
			return nil, err
		}
		acquiredPks = append(acquiredPks, *acquiredKey)
	}

	err = k.keyRepository.SaveAll(acquiredPks)
	if err != nil {
		return acquiredPks, err
	}

	return acquiredPks, nil
}

func (k *keyManager) EncodeUserSymmetricKeyForJWT(userSymmetricKey []byte) string {
	encoded := ""
	for _, b := range userSymmetricKey {
		// Convert each byte in a hex form
		encoded = encoded + fmt.Sprintf("%02X", b)
	}

	return encoded
}

func (k *keyManager) DecodeUserSymmetricKeyForJWT(userSymmetricKey string) (string, error) {
	byteLen := len(userSymmetricKey) / 2
	bytes := make([]byte, byteLen)

	for i := 0; i < byteLen; i++ {
		hex := userSymmetricKey[i*2 : i*2+2]

		b, err := strconv.ParseUint(hex, 16, 8)
		if err != nil {
			return "", err
		}
		bytes[i] = byte(b)
	}

	return string(bytes), nil
}

func (k *keyManager) GetKeysForInvite(
	refUser *models.User,
	refUserSymmetricKey string,
	grantType userGrant.Type,
	inviteCode string,
) ([]encryption.Key, error) {
	pks := make([]encryption.Key, 0)
	for _, key := range refUser.EncryptionKeys {
		if key.UserGrant.AuthorityLevel > grantType.AuthorityLevel {
			// The invited user doesn't get this key
			continue
		}

		pk, pkError := key.PrivateKey.Key([]byte(refUserSymmetricKey))
		if pkError != nil {
			return nil, pkError
		}

		salt := k.cryptoService.GenerateSalt()
		encryptedKey, err := k.cryptoService.CreateEncryptionKeyWithPassword(pk, key.UserGrant, inviteCode, salt)
		if err != nil {
			return nil, err
		}

		pks = append(pks, *encryptedKey)
	}

	return pks, nil
}

func (k *keyManager) CreateKeysForNewUser(
	invite *models.Invite,
	code string,
	password string,
	symmetricKeySalt string,
) ([]encryption.Key, error) {

	sourceKeys := invite.Keys
	if len(sourceKeys) == 0 {
		return nil, lib.Error{Msg: "Invalid invite"}
	}

	finalKeys := make([]encryption.Key, 0)
	for _, key := range sourceKeys {
		tempKeyPassphrase := k.cryptoService.DeriveSecurePassphrase(code, key.Salt)

		sourcePk, err := key.PrivateKey.Key(tempKeyPassphrase)
		if err != nil {
			return nil, lib.Error{Msg: "Invalid invite"}
		}

		encryptedKey, err := k.cryptoService.CreateEncryptionKeyWithPassword(sourcePk, key.UserGrant, password, symmetricKeySalt)
		if err != nil {
			return nil, err
		}

		finalKeys = append(finalKeys, *encryptedKey)
	}

	return finalKeys, nil
}

func (k *keyManager) GetUserSymmetricKey(jwt jwtLib.Token) (string, error) {
	claims := jwt.Claims.(*jwtClaims)
	return k.DecodeUserSymmetricKeyForJWT(claims.EncodedSymmetricKey)
}
