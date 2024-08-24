package dto

type Signup struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Code     string `json:"code"`
	InviteId uint   `json:"inviteId"`
}

type SignInResponse struct {
	Token string `json:"token"`
}
