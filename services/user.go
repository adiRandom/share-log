package services

import (
	"errors"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/models"
	"shareLog/models/dto"
)

type userService struct {
	userRepository repository.UserRepository
	cryptoService  Crypto
}

type UserService interface {
	SignUpWithEmail(signupDto dto.Signup) (*models.User, error)
	SignInWithEmail(email string, password string) (*models.User, error)
}

type UserServiceProvider struct {
}

func (u UserServiceProvider) Provide() UserService {
	userRepository := di.Get[repository.UserRepository]()
	cryptoService := di.Get[Crypto]()
	var instance UserService = &userService{userRepository, cryptoService}
	return instance
}

func (u *userService) SignUpWithEmail(signupDto dto.Signup) (*models.User, error) {
	salt := u.cryptoService.GenerateSalt()
	hashedPassword, err := u.cryptoService.PasswordDerivation(signupDto.Password, salt)
	if err != nil {
		return nil, err
	}

	encryptionKeySalt := u.cryptoService.GenerateSalt()
	derivedKeyFromPassword, err := u.cryptoService.PasswordDerivation(signupDto.Password, encryptionKeySalt)
	encryptionKey, err := u.cryptoService.GetEncryptionKeyForNewUser(signupDto.InviteJWE, derivedKeyFromPassword)
	if err != nil {
		return nil, err
	}

	user := models.User{
		Email:             signupDto.Email,
		PasswordHash:      hashedPassword,
		PasswordSalt:      salt,
		EncryptionKey:     &encryptionKey,
		EncryptionKeySalt: encryptionKeySalt,
	}
	err = u.userRepository.Save(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (u *userService) SignInWithEmail(email string, password string) (*models.User, error) {
	user, err := u.userRepository.GetByEmail(email)
	if err != nil {
		return nil, err
	}

	hashedPassword, err := u.cryptoService.PasswordDerivation(password, user.PasswordSalt)
	if err != nil {
		return nil, err
	}

	if hashedPassword != user.PasswordHash {
		return nil, errors.New("Wrong credentials")
	}

	return user, nil
}
