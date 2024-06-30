package dto

type Signup struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	InviteJWE string `json:"inviteJwe"`
}
