package services

import (
	eciesgo "github.com/ecies/go/v2"
	jwtLib "github.com/golang-jwt/jwt/v5"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/models"
	"shareLog/models/dto"
	"shareLog/models/userGrant"
	"strconv"
)

type auth struct {
	userRepository repository.UserRepository
	keyRepository  repository.KeyRepository
	cryptoService  Crypto
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
	ValidateJWT(token jwtLib.Token) error
	GetAuthUser(jwt jwtLib.Token) *models.User
	GetUserSymmetricKey(jwt jwtLib.Token) string
	SignUpWithEmail(signupDto dto.Signup) (*models.User, error)
	SignInWithEmail(email string, password string) (*models.User, error)
	CreateUserInvite(grantType userGrant.Type, pk *eciesgo.PrivateKey) (*dto.Invite, error)
}

type AuthProvider struct {
}

func (p AuthProvider) Provide() any {
	return &auth{
		userRepository: di.Get[repository.UserRepository](),
		keyRepository:  di.Get[repository.KeyRepository](),
		cryptoService:  di.Get[Crypto](),
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

func (a *auth) ValidateJWT(token jwtLib.Token) error {
	validator := jwtLib.NewValidator(jwtLib.WithExpirationRequired())
	err := validator.Validate(token.Claims)
	if err != nil {
		return err
	}

	return a.validateJWTSignature(token)
}

func (a *auth) validateJWTSignature(token jwtLib.Token) error {
	tokenAsString, err := token.SigningString()
	if err != nil {
		return err
	}

	signature := token.Signature
	key := a.keyRepository.GetJWTVerifyKey()
	return token.Method.Verify(tokenAsString, signature, key)
}

func (a *auth) SignUpWithEmail(signupDto dto.Signup) (*models.User, error) {
	panic("Not implemented")
}

func (a *auth) SignInWithEmail(email string, password string) (*models.User, error) {
	panic("Not implemented")
}

func (a *auth) CreateUserInvite(grantType userGrant.Type, pk *eciesgo.PrivateKey) (*dto.Invite, error) {
	code := a.cryptoService.GenerateSalt()
	salt := a.cryptoService.GenerateSalt()
	_, err := a.cryptoService.CreateEncryptionKey(pk, grantType, code, salt)
	if err != nil {
		return nil, err
	}

	return &dto.Invite{
		Code:  code,
		Salt:  salt,
		Grant: grantType,
	}, nil
}
