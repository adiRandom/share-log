package auth

import (
	"github.com/gin-gonic/gin"
	"shareLog/controllers/base"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/models"
	"shareLog/models/dto"
	"shareLog/models/userGrant"
	"shareLog/services"
)

type authController struct {
	base.BaseController
	userRepo    repository.UserRepository
	authService services.Auth
}

type Controller interface {
	base.LoadableController
}

func (a *authController) LoadController(engine *gin.Engine) {
	auth := engine.Group("/auth")

	{
		auth.POST("/invite", a.inviteUser)
		auth.POST("/signup", a.signUp)
		auth.POST("/signin", a.signIn)
		auth.POST("/signup/init", a.signUpFirstUser)
	}
}

type ControllerProvider struct {
}

func (a ControllerProvider) Provide() any {
	authService := di.Get[services.Auth]()
	baseController := di.Get[base.BaseController]()
	userRepo := di.Get[repository.UserRepository]()

	instance := authController{
		baseController,
		userRepo,
		authService,
	}

	return &instance
}

func (a *authController) inviteUser(c *gin.Context) {
	user := a.GetUser(c)
	if user == nil {
		c.Status(401)
	}

	var createInviteDto dto.CreateInvite
	err := c.BindJSON(&createInviteDto)
	if err != nil {
		c.Status(400)
		return
	}

	pk, err := user.EncryptionKey.PrivateKey.Key([]byte(a.GetUserSymmetricKey(c)))
	if err != nil {
		c.JSON(403, models.GetResponse(
			dto.Error{Code: 403, Message: "Wrong credentials"}))
		return
	}

	invite, _ := a.authService.CreateUserInvite(userGrant.GRANT_OWNER, pk)
	c.JSON(200, models.GetResponse(invite.ToDto()))
}

func (a *authController) signUp(c *gin.Context) {
	signupDto := dto.Signup{}
	err := c.BindJSON(&signupDto)
	if err != nil {
		c.Status(400)
		return
	}

	user, err := a.authService.SignUpWithEmail(signupDto.Email, signupDto.Password, signupDto.Code, signupDto.InviteId)
	if err != nil {
		c.Status(400)
		return
	}

	token, err := a.authService.GenerateAuthToken(user, signupDto.Password)
	if err != nil {
		c.Status(500)
		return
	}

	serializedToken, err := token.CompactSerialize()
	if err != nil {
		c.Status(500)
		return
	}

	response := dto.SignInResponse{
		Token: serializedToken,
	}

	c.JSON(200, models.GetResponse(response))
}

func (a *authController) signUpFirstUser(c *gin.Context) {
	signupDto := dto.FirstUserSignup{}
	err := c.BindJSON(&signupDto)
	if err != nil {
		c.Status(400)
		return
	}

	userCount, err := a.userRepo.Count()
	if err != nil {
		c.Status(500)
		return
	}

	if userCount != 0 {
		c.Status(401)
		return
	}

	user, err := a.authService.SignUpFirstUser(signupDto.Email, signupDto.Password)
	if err != nil {
		c.Status(400)
		return
	}

	token, err := a.authService.GenerateAuthToken(user, signupDto.Password)
	if err != nil {
		println(err.Error())
		c.Status(500)
		return
	}

	serializedToken, err := token.CompactSerialize()
	if err != nil {
		c.Status(500)
		return
	}

	response := dto.SignInResponse{
		Token: serializedToken,
	}

	c.JSON(200, models.GetResponse(response))
}

func (a *authController) signIn(c *gin.Context) {
	loginDto := dto.Login{}
	err := c.BindJSON(&loginDto)
	if err != nil {
		c.Status(400)
		return
	}

	user, err := a.authService.SignInWithEmail(loginDto.Email, loginDto.Password)
	if err != nil {
		c.JSON(403, models.GetResponse(dto.Error{Code: 403, Message: "Wrong credentials"}))
		return
	}

	token, err := a.authService.GenerateAuthToken(user, loginDto.Password)
	if err != nil {
		c.Status(500)
		return
	}

	serializedToken, err := token.CompactSerialize()
	if err != nil {
		c.Status(500)
		return
	}

	response := dto.SignInResponse{
		Token: serializedToken,
	}

	c.JSON(200, models.GetResponse(response))
}
