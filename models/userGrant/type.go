package userGrant

import (
	"database/sql/driver"
	"errors"
	"shareLog/lib"
)

type Type struct {
	Name string
	// Higher means more authority
	AuthorityLevel int
}

var GRANT_CLIENT = Type{
	"client",
	0,
}

var GRANT_OWNER = Type{"owner", 100}

var types = []Type{GRANT_CLIENT, GRANT_OWNER}

func (t *Type) Scan(src any) error {
	typeName, ok := src.(string)
	if !ok {
		return errors.New("Grant type must be string")
	}

	*t = *GetByName(typeName)
	return nil
}

func (t Type) Value() (driver.Value, error) {
	return t.Name, nil
}

func (t Type) GormDataType() string {
	return "text"
}

func GetByName(name string) *Type {
	return lib.Find(types, func(grantType Type) bool {
		return grantType.Name == name
	})
}
