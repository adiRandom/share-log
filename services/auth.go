package services

import (
	eciesgo "github.com/ecies/go/v2"
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

const oneDay = 1000 * 60 * 60 * 24

type auth struct {
	userRepository   repository.UserRepository
	keyRepository    repository.KeyRepository
	inviteRepository repository.InviteRepository
	cryptoService    Crypto
}

/*
SymmetricKey is the key used by this userGrant to secure all their other encryption keys
*/
type jwtClaims struct {
	jwtLib.RegisteredClaims
	SymmetricKey string `json:"userSymmetricKey"`
}

func (j jwtClaims) Validate() error {
	// No custom validation yet
	return nil
}

type Auth interface {
	ParseAndValidateJWT(signedJwt string) (*jwtLib.Token, error)
	GetAuthUser(jwt jwtLib.Token) *models.User
	GetUserSymmetricKey(jwt jwtLib.Token) string
	GenerateAuthToken(user *models.User, password string) (*jose.JSONWebEncryption, error)
	SignUpWithEmail(email string, password string, code string, inviteId uint) (*models.User, error)
	SignInWithEmail(email string, password string) (*models.User, error)
	CreateUserInvite(grantType userGrant.Type, pks []eciesgo.PrivateKey) (*models.Invite, error)
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

func (a *auth) GetUserSymmetricKey(jwt jwtLib.Token) string {
	claims := jwt.Claims.(*jwtClaims)
	return claims.SymmetricKey
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
	invite := a.inviteRepository.GetById(inviteId)
	if invite == nil {
		return nil, lib.Error{Msg: "Invalid invite id"}
	}

	isValidCode := lib.CompareHashAndPassword(invite.CodeHash, code, invite.HashSalt)
	if !isValidCode {
		return nil, lib.Error{Msg: "Invalid invite code"}
	}

	return invite, nil
}

func (a *auth) extractSourcePrivateKeysFromInvite(invite *models.Invite, code string) ([]eciesgo.PrivateKey, error) {
	tempKeyPassphrase := a.cryptoService.DeriveSecurePassphrase(code, invite.DeriveSalt)

	// TODO: Delete temp key after invite
	sourceKey := invite.Keys
	if len(sourceKey) == 0 {
		return nil, lib.Error{Msg: "Invalid invite"}
	}

	sourcePks := make([]eciesgo.PrivateKey, 0)
	for _, sourceKey := range sourceKey {
		sourcePk, err := sourceKey.PrivateKey.Key(tempKeyPassphrase)
		if err != nil {
			return nil, lib.Error{Msg: "Invalid invite"}
		}

		sourcePks = append(sourcePks, *sourcePk)
	}

	return sourcePks, nil
}

func (a *auth) SignUpWithEmail(email string, password string, code string, inviteId uint) (*models.User, error) {
	invite, err := a.extractInvite(inviteId, code)
	if err != nil {
		return nil, err
	}
	sourcePks, err := a.extractSourcePrivateKeysFromInvite(invite, code)

	keys := make([]encryption.Key, 0)
	keySalt := a.cryptoService.GenerateSalt()
	for _, key := range sourcePks {
		encryptedKey, err := a.cryptoService.CreateEncryptionKey(&key, invite.Grant, password, keySalt)
		if err != nil {
			return nil, err
		}
		keys = append(keys, *encryptedKey)
	}

	return a.signUpUserWithKeys(email, password, keys, keySalt)
}

func (a *auth) signUpUserWithKeys(email string, password string, keys []encryption.Key, keySalt string) (*models.User, error) {
	passwordSalt := a.cryptoService.GenerateSalt()
	hashedPassword, err := lib.HashPassword(password, passwordSalt)
	if err != nil {
		return nil, err
	}

	for i, _ := range keys {
		keys[i].OwnerType = encryption.USER_ENTITY_TYPE
	}

	user := models.User{
		Email:             email,
		PasswordHash:      hashedPassword,
		PasswordSalt:      passwordSalt,
		EncryptionKeySalt: keySalt,
		EncryptionKeys:    keys,
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

func (a *auth) CreateUserInvite(grantType userGrant.Type, sourcePks []eciesgo.PrivateKey) (*models.Invite, error) {
	code := a.cryptoService.GenerateSalt()
	deriveSalt := a.cryptoService.GenerateSalt()
	hashSalt := a.cryptoService.GenerateSalt()

	keys := make([]encryption.Key, 0)
	for _, sourcePk := range sourcePks {
		key, err := a.cryptoService.CreateEncryptionKey(&sourcePk, grantType, code, deriveSalt)
		if err != nil {
			return nil, err
		}
		key.OwnerType = encryption.INVITE_ENTITY_TYPE
		keys = append(keys, *key)
	}

	invite, err := models.NewInvite(keys, code, deriveSalt, hashSalt, grantType)
	if err != nil {
		return nil, err
	}

	err = a.inviteRepository.Save(invite)

	return invite, nil
}

func (a *auth) GenerateAuthToken(user *models.User, password string) (*jose.JSONWebEncryption, error) {
	userSymmetricKey := a.cryptoService.DeriveUserSymmetricKey(password, user.EncryptionKeySalt)
	jwt := a.createJWT(user, userSymmetricKey)
	x := jwt.Claims.(jwtClaims).SymmetricKey
	print(x)
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
		userSymmetricKey,
	}

	signingMethod := jwtLib.SigningMethodES512

	return jwtLib.NewWithClaims(signingMethod, claims)
}

func (a *auth) SignUpFirstUser(email string, password string) (*models.User, error) {
	keySalt := a.cryptoService.GenerateSalt()
	ownerKey, err := a.cryptoService.CreateFirstEncryptionKey(userGrant.GRANT_OWNER, password, keySalt)
	if err != nil {
		return nil, err
	}

	clientKey, err := a.cryptoService.CreateFirstEncryptionKey(userGrant.GRANT_CLIENT, password, keySalt)
	if err != nil {
		return nil, err
	}

	keys := []encryption.Key{*ownerKey, *clientKey}

	return a.signUpUserWithKeys(email, password, keys, keySalt)
}
