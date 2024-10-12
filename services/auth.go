package services

import (
	"fmt"
	"github.com/go-jose/go-jose/v4"
	jwtLib "github.com/golang-jwt/jwt/v5"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/lib"
	"shareLog/models"
	"shareLog/models/encryption"
	"shareLog/models/userGrant"
	"strconv"
	"time"
)

type auth struct {
	userRepository   repository.UserRepository
	keyRepository    repository.KeyRepository
	inviteRepository repository.InviteRepository
	cryptoService    Crypto
}

/*
EncodedSymmetricKey is the key used by this userGrant to secure all their other encryption keys,
encoded in appended hex
*/
type jwtClaims struct {
	jwtLib.RegisteredClaims
	EncodedSymmetricKey string `json:"userSymmetricKey"`
}

func (j jwtClaims) Validate() error {
	// No custom validation yet
	return nil
}

type Auth interface {
	ParseAndValidateJWT(signedJwt string) (*jwtLib.Token, error)
	GetAuthUser(jwt jwtLib.Token) *models.User
	GetUserSymmetricKey(jwt jwtLib.Token) (string, error)
	GenerateAuthToken(user *models.User, password string) (*jose.JSONWebEncryption, error)
	SignUpWithEmail(email string, password string, code string, inviteId uint) (*models.User, error)
	SignInWithEmail(email string, password string) (*models.User, error)
	CreateUserInvite(grantType userGrant.Type, refUser *models.User, refUserSymmetricKey string) (*models.Invite, error)
	SignUpFirstUser(email string, password string) (*models.User, error)
}

type AuthProvider struct {
}

func (p AuthProvider) Provide() any {
	return &auth{
		userRepository:   di.Get[repository.UserRepository](),
		keyRepository:    di.Get[repository.KeyRepository](),
		inviteRepository: di.Get[repository.InviteRepository](),
		cryptoService:    di.Get[Crypto](),
	}
}

func (a *auth) GetAuthUser(jwt jwtLib.Token) *models.User {
	claims := jwt.Claims.(*jwtClaims)
	userId, err := strconv.ParseInt(claims.Subject, 10, 32)
	if err != nil {
		println(err)
		return nil
	}
	user := a.userRepository.GetByIdWithPrivateKeys(uint(userId))
	return user
}

func (a *auth) GetUserSymmetricKey(jwt jwtLib.Token) (string, error) {
	claims := jwt.Claims.(*jwtClaims)
	return a.decodeUserSymmetricKeyForJWT(claims.EncodedSymmetricKey)
}

func (a *auth) ParseAndValidateJWT(signedJwt string) (*jwtLib.Token, error) {
	token, err := jwtLib.ParseWithClaims(signedJwt, &jwtClaims{}, func(token *jwtLib.Token) (interface{}, error) {
		return a.keyRepository.GetJWTPubKey()
	})
	if err != nil {
		return nil, err
	}

	tokenValidator := jwtLib.NewValidator(jwtLib.WithExpirationRequired())
	err = tokenValidator.Validate(token.Claims)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (a *auth) extractInvite(inviteId uint, code string) (*models.Invite, error) {
	invite, err := a.inviteRepository.GetByIdWithKeys(inviteId)
	if err != nil {
		return nil, err
	}
	if invite == nil {
		return nil, lib.Error{Msg: "Invalid invite id"}
	}

	isValidCode := lib.CompareHashAndPassword(invite.CodeHash, code, invite.HashSalt)
	if !isValidCode {
		return nil, lib.Error{Msg: "Invalid invite code"}
	}

	return invite, nil
}

func (a *auth) createKeysForNewUser(invite *models.Invite, code string, password string, keySalt string) ([]encryption.Key, error) {
	tempKeyPassphrase := a.cryptoService.DeriveSecurePassphrase(code, invite.DeriveSalt)

	sourceKeys := invite.Keys
	if len(sourceKeys) == 0 {
		return nil, lib.Error{Msg: "Invalid invite"}
	}

	finalKeys := make([]encryption.Key, 0)
	for _, key := range sourceKeys {
		sourcePk, err := key.PrivateKey.Key(tempKeyPassphrase)
		if err != nil {
			return nil, lib.Error{Msg: "Invalid invite"}
		}

		encryptedKey, err := a.cryptoService.CreateEncryptionKey(sourcePk, key.UserGrant, password, keySalt)
		if err != nil {
			return nil, err
		}

		finalKeys = append(finalKeys, *encryptedKey)
	}

	return finalKeys, nil
}

func (a *auth) clearInviteData(invite *models.Invite) error {
	err := a.inviteRepository.Delete(invite)
	if err != nil {
		return err
	}

	err = a.keyRepository.BatchDeletePermanently(invite.Keys)
	if err != nil {
		return err
	}

	return nil
}

func (a *auth) SignUpWithEmail(email string, password string, code string, inviteId uint) (*models.User, error) {
	invite, err := a.extractInvite(inviteId, code)
	if err != nil {
		return nil, err
	}
	keySalt := a.cryptoService.GenerateSalt()

	keys, err := a.createKeysForNewUser(invite, code, password, keySalt)
	if err != nil {
		return nil, err
	}

	clearErr := a.clearInviteData(invite)
	if clearErr != nil {
		return nil, err
	}

	return a.signUpUserWithKeys(email, password, keys, keySalt, invite.Grant)
}

func (a *auth) signUpUserWithKeys(email string, password string, keys []encryption.Key, keySalt string, grant userGrant.Type) (*models.User, error) {
	passwordSalt := a.cryptoService.GenerateSalt()
	hashedPassword, err := lib.HashPassword(password, passwordSalt)
	if err != nil {
		return nil, err
	}

	user := models.User{
		Email:             email,
		PasswordHash:      hashedPassword,
		PasswordSalt:      passwordSalt,
		EncryptionKeySalt: keySalt,
		EncryptionKeys:    keys,
		Grant:             grant,
	}
	err = a.userRepository.Save(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (a *auth) SignInWithEmail(email string, password string) (*models.User, error) {
	user, err := a.userRepository.GetByEmail(email)
	if err != nil {
		return nil, err
	}

	if hashMatch := lib.CompareHashAndPassword(user.PasswordHash, password, user.PasswordSalt); !hashMatch {
		return nil, lib.Error{Msg: "Wrong email or password"}
	}

	return user, err
}

func (a *auth) CreateUserInvite(grantType userGrant.Type, refUser *models.User, refUserSymmetricKey string) (*models.Invite, error) {
	code := a.cryptoService.GenerateSalt()
	print(code)
	deriveSalt := a.cryptoService.GenerateSalt()
	hashSalt := a.cryptoService.GenerateSalt()

	keys, err := a.getKeysForInvite(
		refUser,
		refUserSymmetricKey,
		grantType,
		code,
		deriveSalt,
	)
	if err != nil {
		return nil, err
	}

	invite, err := models.NewInvite(keys, code, deriveSalt, hashSalt, grantType)
	if err != nil {
		return nil, err
	}

	err = a.inviteRepository.Save(invite)

	return invite, nil
}

func (a *auth) getKeysForInvite(
	refUser *models.User,
	refUserSymmetricKey string,
	grantType userGrant.Type,
	inviteCode string,
	inviteSalt string,
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

		encryptedKey, err := a.cryptoService.CreateEncryptionKey(pk, key.UserGrant, inviteCode, inviteSalt)
		if err != nil {
			return nil, err
		}

		pks = append(pks, *encryptedKey)
	}

	return pks, nil
}

func (a *auth) GenerateAuthToken(user *models.User, password string) (*jose.JSONWebEncryption, error) {
	userSymmetricKey := a.cryptoService.DeriveUserSymmetricKey(password, user.EncryptionKeySalt)
	jwt := a.createJWT(user, userSymmetricKey)
	return a.cryptoService.CreateJwe(jwt)
}

func (a *auth) createJWT(user *models.User, userSymmetricKey string) *jwtLib.Token {
	exp := time.Now().Add(time.Hour * 24)

	claims := jwtClaims{
		jwtLib.RegisteredClaims{
			Subject: strconv.Itoa(int(user.ID)),
			ExpiresAt: &jwtLib.NumericDate{
				Time: exp,
			},
		},
		a.encodeUserSymmetricKeyForJWT([]byte(userSymmetricKey)),
	}

	signingMethod := jwtLib.SigningMethodES512

	return jwtLib.NewWithClaims(signingMethod, claims)
}

func (a *auth) SignUpFirstUser(email string, password string) (*models.User, error) {
	keySalt := a.cryptoService.GenerateSalt()
	ownerKey, err := a.cryptoService.CreateFirstEncryptionKey(userGrant.Types.GrantOwner, password, keySalt)
	if err != nil {
		return nil, err
	}

	clientKey, err := a.cryptoService.CreateFirstEncryptionKey(userGrant.Types.GrantClient, password, keySalt)
	if err != nil {
		return nil, err
	}

	keys := []encryption.Key{*ownerKey, *clientKey}

	return a.signUpUserWithKeys(email, password, keys, keySalt, userGrant.Types.GrantOwner)
}

func (a *auth) encodeUserSymmetricKeyForJWT(userSymmetricKey []byte) string {
	encoded := ""
	for _, b := range userSymmetricKey {
		// Convert each byte in a hex form
		encoded = encoded + fmt.Sprintf("%02X", b)
	}

	return encoded
}

func (a *auth) decodeUserSymmetricKeyForJWT(userSymmetricKey string) (string, error) {
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
