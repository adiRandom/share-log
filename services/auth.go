package services

import (
	eciesgo "github.com/ecies/go/v2"
	"github.com/go-jose/go-jose/v4"
	jwtLib "github.com/golang-jwt/jwt/v5"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/lib"
	"shareLog/models"
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
symmetricKey is the key used by this userGrant to secure all their other encryption keys
*/
type jwtClaims struct {
	jwtLib.RegisteredClaims
	symmetricKey string
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
	CreateUserInvite(grantType userGrant.Type, pk *eciesgo.PrivateKey) (*models.Invite, error)
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
	claims := jwt.Claims.(jwtClaims)
	userId, err := strconv.ParseInt(claims.Subject, 10, 32)
	if err != nil {
		println(err)
		return nil
	}

	user := a.userRepository.GetById(uint(userId))
	return user
}

func (a *auth) GetUserSymmetricKey(jwt jwtLib.Token) string {
	claims := jwt.Claims.(jwtClaims)
	return claims.symmetricKey
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

func (a *auth) extractSourcePrivateKeyFromInvite(invite *models.Invite, code string) (*eciesgo.PrivateKey, error) {
	tempKeyPassphrase := a.cryptoService.DeriveSecurePassphrase(code, invite.DeriveSalt)

	sourceKey := a.keyRepository.GetById(invite.KeyId)
	if sourceKey == nil || sourceKey.PrivateKey == nil {
		return nil, lib.Error{Msg: "Invalid key"}
	}
	sourcePk, err := sourceKey.PrivateKey.Key(tempKeyPassphrase)
	if err != nil {
		return nil, lib.Error{Msg: "Invalid invite"}
	}

	return sourcePk, nil
}

func (a *auth) SignUpWithEmail(email string, password string, code string, inviteId uint) (*models.User, error) {
	invite, err := a.extractInvite(inviteId, code)
	if err != nil {
		return nil, err
	}
	sourcePk, err := a.extractSourcePrivateKeyFromInvite(invite, code)

	keySalt := a.cryptoService.GenerateSalt()
	key, err := a.cryptoService.CreateEncryptionKey(sourcePk, invite.Grant, password, keySalt)
	if err != nil {
		return nil, err
	}

	passwordSalt := a.cryptoService.GenerateSalt()
	hashedPassword, err := lib.HashPassword(password, passwordSalt)
	if err != nil {
		return nil, err
	}

	user := models.User{
		Email:             email,
		PasswordHash:      hashedPassword,
		PasswordSalt:      passwordSalt,
		EncryptionKey:     key,
		EncryptionKeySalt: keySalt,
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

func (a *auth) CreateUserInvite(grantType userGrant.Type, sourcePk *eciesgo.PrivateKey) (*models.Invite, error) {
	code := a.cryptoService.GenerateSalt()
	// TODO: Remove this
	print(code)
	deriveSalt := a.cryptoService.GenerateSalt()
	hashSalt := a.cryptoService.GenerateSalt()

	key, err := a.cryptoService.CreateEncryptionKey(sourcePk, grantType, code, deriveSalt)
	if err != nil {
		return nil, err
	}

	invite, err := models.NewInvite(key.ID, code, deriveSalt, hashSalt, grantType)
	if err != nil {
		return nil, err
	}

	err = a.inviteRepository.Save(invite)

	return invite, nil
}

func (a *auth) GenerateAuthToken(user *models.User, password string) (*jose.JSONWebEncryption, error) {
	userSymmetricKey := string(a.cryptoService.DeriveSecurePassphrase(password, user.EncryptionKeySalt))
	jwt := a.createJWT(user, userSymmetricKey)
	return a.cryptoService.CreateJwe(jwt)
}

func (a *auth) createJWT(user *models.User, userSymmetricKey string) *jwtLib.Token {
	exp := time.Now().Add(oneDay)

	claims := jwtClaims{
		jwtLib.RegisteredClaims{
			Subject: strconv.Itoa(int(user.ID)),
			ExpiresAt: &jwtLib.NumericDate{
				Time: exp,
			},
		},
		userSymmetricKey,
	}

	signingMethod := jwtLib.SigningMethodES256

	return jwtLib.NewWithClaims(signingMethod, claims)
}
