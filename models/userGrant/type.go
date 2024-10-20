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
const partialOwnerType = "partialOwner"
const appClientType = "app"

type TypeMap struct {
	GrantClient       Type
	GrantShared       Type
	GrantPartialOwner Type
	GrantOwner        Type
	GrantApp          Type
}

var Types = TypeMap{
	GrantOwner:        Type{ownerType, 1000},
	GrantPartialOwner: Type{partialOwnerType, 200},
	GrantShared:       Type{sharedType, 100},
	GrantClient: Type{
		clientType,
		100,
	},
	GrantApp: Type{
		appClientType,
		50,
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
	case partialOwnerType:
		return &Types.GrantPartialOwner
	case clientType:
		return &Types.GrantClient
	case appClientType:
		return &Types.GrantApp
	}

	return nil
}
