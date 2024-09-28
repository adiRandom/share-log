package dto

type Invite struct {
	InviteId uint `json:"inviteId"`
}

type CreateInvite struct {
	Grant string `json:"grant"`
}
