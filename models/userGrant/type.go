package userGrant

import (
	"database/sql/driver"
	"errors"
)

type Type struct {
	Name string
	// Higher means more authority
	AuthorityLevel int
}

const ownerType = "owner"
const clientType = "client"
const sharedType = "shared"

type TypeMap struct {
	GrantClient Type
	GrantShared Type
	GrantOwner  Type
}

var Types = TypeMap{
	GrantOwner:  Type{ownerType, 100},
	GrantShared: Type{sharedType, 10},
	GrantClient: Type{
		clientType,
		0,
	},
}

func (t *Type) Scan(src any) error {
	typeName, ok := src.(string)
	if !ok {
		return errors.New("Grant type must be string")
	}

	*t = *Types.GetByName(typeName)
	return nil
}

func (t Type) Value() (driver.Value, error) {
	return t.Name, nil
}

func (t Type) GormDataType() string {
	return "text"
}

func (t TypeMap) GetByName(name string) *Type {
	switch name {
	case ownerType:
		return &Types.GrantOwner
	case sharedType:
		return &Types.GrantShared
	case clientType:
		return &Types.GrantClient
	}

	return nil
}
