package dto

type LogPermissionRequest struct {
	Id       uint `json:"id"`
	LogId    uint `json:"logId"`
	Status   string
	Acquired bool
}
