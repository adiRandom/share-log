package dto

import "shareLog/models/userGrant"

type Signup struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	InviteDto Invite `json:"invite"`
}

type Invite struct {
	KeyId uint           `json:"keyId"`
	Code  string         `json:"code"`
	Salt  string         `json:"salt"`
	Grant userGrant.Type `json:"grant"`
}

type CreateInvite struct {
	Grant userGrant.Type `json:"grant"`
}
