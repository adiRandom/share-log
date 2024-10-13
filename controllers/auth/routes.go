package auth

import (
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"shareLog/controllers/base"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/lib"
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
		auth.POST("/signup", a.signUp)
		auth.POST("/signin", a.signIn)
		auth.POST("/signup/init", a.signUpFirstUser)
	}

	invite := engine.Group("/auth/invite")
	a.WithAuth(invite)
	{
		invite.POST("/", a.inviteUser)
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

	var createInviteDto dto.CreateInvite
	err := c.BindJSON(&createInviteDto)
	if err != nil {
		c.Status(400)
		return
	}

	userGrantType := userGrant.Types.GetByName(createInviteDto.Grant)

	invite, _ := a.authService.CreateUserInvite(*userGrantType, user, a.GetUserSymmetricKey(c))
	c.JSON(200, models.GetResponse(invite.ToDto()))
}

func (a *authController) userAlreadyExists(c *gin.Context, email string) (bool, error) {
	user, err := a.userRepo.GetByEmail(email)
	if user != nil && err == nil {
		c.Status(403)
		return true, nil
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(500, models.GetResponse(dto.Error{Code: 500, Message: err.Error()}))
		return false, err
	}

	return false, nil
}

func (a *authController) getAuthToken(user *models.User, password string) (*string, error) {
	token, err := a.authService.GenerateAuthToken(user, password)
	if err != nil {
		return nil, err
	}

	serializedToken, err := token.CompactSerialize()
	if err != nil {
		return nil, err
	}

	return &serializedToken, nil
}

func (a *authController) doSignupValidations(c *gin.Context, email, password string) bool {
	userAlreadyExists, err := a.userAlreadyExists(c, email)
	if userAlreadyExists || err != nil {
		return false
	}

	passwordErrors := lib.IsPasswordValid(password)
	if len(passwordErrors) != 0 {
		mappedErrors := lib.Map(passwordErrors, func(err lib.PasswordError) string {
			return err.Message()
		})
		c.JSON(400, models.GetResponse(mappedErrors))
		return false
	}

	return true
}

func (a *authController) signUp(c *gin.Context) {
	signupDto := dto.Signup{}
	err := c.BindJSON(&signupDto)
	if err != nil {
		c.Status(400)
		return
	}

	canSignUp := a.doSignupValidations(c, signupDto.Email, signupDto.Password)
	if !canSignUp {
		return
	}

	user, err := a.authService.SignUpWithEmail(signupDto.Email, signupDto.Password, signupDto.Code, signupDto.InviteId)
	if err != nil {
		c.Status(400)
		return
	}

	token, err := a.getAuthToken(user, signupDto.Password)
	if err != nil {
		c.Status(500)
		return
	}

	response := dto.SignInResponse{
		Token: *token,
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

	canSignUp := a.doSignupValidations(c, signupDto.Email, signupDto.Password)
	if !canSignUp {
		return
	}

	user, err := a.authService.SignUpFirstUser(signupDto.Email, signupDto.Password)
	if err != nil {
		c.Status(400)
		return
	}

	token, err := a.getAuthToken(user, signupDto.Password)
	if err != nil {
		c.Status(500)
		return
	}

	response := dto.SignInResponse{
		Token: *token,
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

	token, err := a.getAuthToken(user, loginDto.Password)
	if err != nil {
		c.Status(500)
		return
	}

	response := dto.SignInResponse{
		Token: *token,
	}

	c.JSON(200, models.GetResponse(response))
}
