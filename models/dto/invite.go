package dto

import "shareLog/models/userGrant"

type Invite struct {
	InviteId uint `json:"inviteId"`
}

type CreateInvite struct {
	Grant userGrant.Type `json:"grant"`
}
