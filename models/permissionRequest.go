package models

import "gorm.io/gorm"

type PermissionRequest struct {
	gorm.Model
	LogID  uint `gorm:"unique"`
	Log    Log
	Status PermissionRequestStatus
}
