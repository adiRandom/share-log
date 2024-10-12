package models

import (
	"gorm.io/gorm"
)

/*
Log is a struct that represents a log in the database.

	DoubleEncryptedStackTrace: The stack trace that is once encrypted with the public key of the client
	and then encrypted with the public key of the data owner
*/
type Log struct {
	gorm.Model
	DoubleEncryptedStackTrace string
}

func NewLog(doubleEncryptedStackTrace string) Log {
	return Log{
		DoubleEncryptedStackTrace: doubleEncryptedStackTrace,
	}
}

type DecryptedLog struct {
	StackTrace string
}

func NewDecryptedLog(stackTrace string) *DecryptedLog {
	return &DecryptedLog{
		StackTrace: stackTrace,
	}
}
