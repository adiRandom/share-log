package services

import (
	jwtLib "github.com/golang-jwt/jwt/v4"
	"shareLog/data/repository"
	"shareLog/models"
	"strconv"
)

type auth struct {
	userRepository repository.UserRepository
}

/*
symmetricKey is the key used by this user to secure all their other encryption keys
*/
type jwtClaims struct {
	jwtLib.RegisteredClaims
	symmetricKey string
}

func (a *auth) ValidateJWT(token jwtLib.Token) error {
	//TODO implement me
	panic("implement me")
}

type Auth interface {
	ValidateJWT(token jwtLib.Token) error
	GetAuthUser(jwt jwtLib.Token) *models.User
	GetUserSymmetricKey(jwt jwtLib.Token) string
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
