package services

import (
	"errors"
	jwtLib "github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"shareLog/data/repository"
	"shareLog/models"
	"shareLog/models/dto"
	"strconv"
)

type auth struct {
	userRepository repository.UserRepository
	keyRepository  repository.KeyRepository
	cryptoService  Crypto
}

/*
symmetricKey is the key used by this user to secure all their other encryption keys
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
}

type AuthProvider struct {
}

func (p AuthProvider) Provide() Auth {
	return &auth{}
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
	salt := a.cryptoService.GenerateSalt()
	hashedPassword, err := a.cryptoService.PasswordDerivation(signupDto.Password, salt)
	if err != nil {
		return nil, err
	}

	encryptionKeySalt := a.cryptoService.GenerateSalt()
	derivedKeyFromPassword, err := a.cryptoService.PasswordDerivation(signupDto.Password, encryptionKeySalt)
	encryptionKey, err := a.cryptoService.GetEncryptionKeyForNewUser(signupDto.InviteJWE, derivedKeyFromPassword)
	if err != nil {
		return nil, err
	}

	user := models.User{
		Email:             signupDto.Email,
		PasswordHash:      hashedPassword,
		PasswordSalt:      salt,
		EncryptionKey:     encryptionKey,
		EncryptionKeySalt: encryptionKeySalt,
	}
	err = a.userRepository.Save(&user)
	if err != nil {
		return nil, err
	}

	// TODO: Generate JWT and JWE

	return &user, nil
}

func (a *auth) SignInWithEmail(email string, password string) (*models.User, error) {
	user, err := a.userRepository.GetByEmail(email)
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(password), []byte(user.PasswordHash)); err != nil {
		return nil, errors.New("Wrong credentials")
	}

	// TODO: Generate JWT and JWE

	return user, nil
}
