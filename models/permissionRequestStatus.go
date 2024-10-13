package models

import (
	"database/sql/driver"
	"errors"
)

type PermissionRequestStatus struct {
	Status string
}

const approved = "approved"
const pending = "pending"
const denied = "denied"

type PermissionRequestMap struct {
	Approved PermissionRequestStatus
	Pending  PermissionRequestStatus
	Denied   PermissionRequestStatus
}

var PermissionRequestStatuses = PermissionRequestMap{
	Approved: PermissionRequestStatus{approved},
	Pending:  PermissionRequestStatus{pending},
	Denied:   PermissionRequestStatus{denied},
}

func (p *PermissionRequestStatus) Scan(src any) error {
	status, ok := src.(string)
	if !ok {
		return errors.New("Status must be string.")
	}

	*p = *PermissionRequestStatuses.GetByName(status)
	return nil
}

func (p PermissionRequestStatus) Value() (driver.Value, error) {
	return p.Status, nil
}

func (p PermissionRequestStatus) GormDataType() string {
	return "text"
}

func (p *PermissionRequestMap) GetByName(name string) *PermissionRequestStatus {
	switch name {
	case approved:
		return &PermissionRequestStatuses.Approved
	case pending:
		return &PermissionRequestStatuses.Pending
	case denied:
		return &PermissionRequestStatuses.Denied
	default:
		return nil
	}
}
