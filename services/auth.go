package services

import (
	"github.com/go-jose/go-jose/v4"
	jwtLib "github.com/golang-jwt/jwt/v5"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/lib"
	"shareLog/models"
	"shareLog/models/encryption"
	"shareLog/models/userGrant"
	"slices"
	"strconv"
	"time"
)

type auth struct {
	userRepository   repository.UserRepository
	keyRepository    repository.KeyRepository
	inviteRepository repository.InviteRepository
	apiKeyRepository repository.ApiKeyRepository
	mailer           Mailer
	cryptoService    Crypto
	keyManager       KeyManager
}

/*
EncodedSymmetricKey is the key used by this userGrant to secure all their other encryption keys,
encoded in appended hex
*/
type jwtClaims struct {
	jwtLib.RegisteredClaims
	Grant               string `json:"grant"`
	EncodedSymmetricKey string `json:"userSymmetricKey"`
	EncodedPubKey       string `json:"encodedPubKey"`
}

func (j jwtClaims) Validate() error {
	// No custom validation yet
	return nil
}

type Auth interface {
	ParseAndValidateJWT(signedJwt string) (*jwtLib.Token, error)
	GetAuthUser(jwt jwtLib.Token) *models.User
	GenerateUserAuthToken(user *models.User, password string) (*jose.JSONWebEncryption, error)
	GenerateAppAuthToken(apiKey string) (*jwtLib.Token, error)
	SignUpWithEmail(email string, password string, code string, inviteId uint) (*models.User, error)
	SignInWithEmail(email string, password string) (*models.User, error)
	CreateUserInvite(grantType userGrant.Type, refUser *models.User, refUserSymmetricKey string) (*models.Invite, error)
	SignUpFirstUser(email string, password string) (*models.User, error)
	GenerateApiKey(user *models.User) (models.ApiKey, error)
	GetAuthGrant(jwt jwtLib.Token) userGrant.Type
}

type AuthProvider struct {
}

func (p AuthProvider) Provide() any {
	return &auth{
		userRepository:   di.Get[repository.UserRepository](),
		keyRepository:    di.Get[repository.KeyRepository](),
		inviteRepository: di.Get[repository.InviteRepository](),
		apiKeyRepository: di.Get[repository.ApiKeyRepository](),
		cryptoService:    di.Get[Crypto](),
		mailer:           di.Get[Mailer](),
		keyManager:       di.Get[KeyManager](),
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

	keys, err := a.keyManager.CreateKeysForNewUser(invite, code, password, keySalt)
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

	if grant == userGrant.Types.GrantClient {
		acquiredSharedKeys, err := a.keyManager.AcquireSharedKeys(&user, password, keySalt)
		if err != nil {
			return nil, err
		}

		user.EncryptionKeys = slices.Concat(user.EncryptionKeys, acquiredSharedKeys)
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

	if user.Grant == userGrant.Types.GrantClient {
		acquiredSharedKeys, err := a.keyManager.AcquireSharedKeys(user, password, user.EncryptionKeySalt)
		if err != nil {
			return nil, err
		}

		user.EncryptionKeys = slices.Concat(user.EncryptionKeys, acquiredSharedKeys)
	}

	return user, err
}

func (a *auth) CreateUserInvite(grantType userGrant.Type, refUser *models.User, refUserSymmetricKey string) (*models.Invite, error) {
	code := a.cryptoService.GenerateSalt()
	hashSalt := a.cryptoService.GenerateSalt()

	keys, err := a.keyManager.GetKeysForInvite(
		refUser,
		refUserSymmetricKey,
		grantType,
		code,
	)
	if err != nil {
		return nil, err
	}

	invite, err := models.NewInvite(keys, code, hashSalt, grantType)
	if err != nil {
		return nil, err
	}

	err = a.inviteRepository.Save(invite)

	a.mailer.EmailInviteCode(code)
	return invite, nil
}

func (a *auth) GenerateUserAuthToken(user *models.User, password string) (*jose.JSONWebEncryption, error) {
	userSymmetricKey := a.cryptoService.DeriveUserSymmetricKey(password, user.EncryptionKeySalt)
	jwt := a.createUserJWT(user, userSymmetricKey)
	return a.cryptoService.CreateJwe(jwt)
}

func (a *auth) GenerateAppAuthToken(apiKey string) (*jwtLib.Token, error) {
	// Check if api key is valid
	apiKeyModel := a.apiKeyRepository.GetByKey(apiKey)
	if apiKeyModel == nil {
		return nil, lib.Error{Msg: "Invalid api key"}
	}

	return a.createAppJWT(*apiKeyModel), nil
}

func (a *auth) createUserJWT(user *models.User, userSymmetricKey string) *jwtLib.Token {
	exp := time.Now().Add(time.Hour * 24)

	claims := jwtClaims{
		RegisteredClaims: jwtLib.RegisteredClaims{
			Subject: strconv.Itoa(int(user.ID)),
			ExpiresAt: &jwtLib.NumericDate{
				Time: exp,
			},
		},
		Grant:               user.Grant.Name,
		EncodedSymmetricKey: a.keyManager.EncodeEncryptionKeyForJWT([]byte(userSymmetricKey)),
	}

	signingMethod := jwtLib.SigningMethodES512

	return jwtLib.NewWithClaims(signingMethod, claims)
}
func (a *auth) createAppJWT(key models.ApiKey) *jwtLib.Token {
	exp := time.Now().Add(time.Hour * 24)

	claims := jwtClaims{
		RegisteredClaims: jwtLib.RegisteredClaims{
			ExpiresAt: &jwtLib.NumericDate{
				Time: exp,
			},
		},
		Grant:         userGrant.Types.GrantApp.Name,
		EncodedPubKey: key.EncryptionKey.PublicKey.Key.Hex(true),
	}

	signingMethod := jwtLib.SigningMethodES512

	return jwtLib.NewWithClaims(signingMethod, claims)
}

func (a *auth) SignUpFirstUser(email string, password string) (*models.User, error) {
	keySalt := a.cryptoService.GenerateSalt()
	ownerKey, err := a.cryptoService.CreateNewEncryptionKey(userGrant.Types.GrantOwner, password, keySalt)
	if err != nil {
		return nil, err
	}

	clientKey, err := a.cryptoService.CreateNewEncryptionKey(userGrant.Types.GrantClient, password, keySalt)
	if err != nil {
		return nil, err
	}

	keys := []encryption.Key{*ownerKey, *clientKey}

	return a.signUpUserWithKeys(email, password, keys, keySalt, userGrant.Types.GrantOwner)
}

func (a *auth) GenerateApiKey(user *models.User) (models.ApiKey, error) {
	apiKey := a.cryptoService.GenerateSalt()
	encryptionKey := lib.Find(user.EncryptionKeys, func(key encryption.Key) bool {
		return key.UserGrant == userGrant.Types.GrantClient
	})

	apiKeyModel := models.ApiKey{
		Key:             apiKey,
		EncryptionKey:   encryptionKey,
		EncryptionKeyId: encryptionKey.ID,
	}
	err := a.apiKeyRepository.Save(&apiKeyModel)
	if err != nil {
		return apiKeyModel, err
	}

	return apiKeyModel, nil
}

func (a *auth) GetAuthGrant(jwt jwtLib.Token) userGrant.Type {
	claims := jwt.Claims.(*jwtClaims)
	return *userGrant.Types.GetByName(claims.Grant)
}
