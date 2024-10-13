package lib

import (
	"fmt"
	"shareLog/config"
	"strings"
)

const numbers = "0123456789"
const specials = "!@#$%^&*()-_+=,.<>/?;:'\"\\|[]{}`~"

type passwordError struct {
	message string
}

type PasswordError interface {
	Message() string
}

func (p passwordError) Message() string {
	return p.message
}

var minLenError = passwordError{
	message: fmt.Sprintf("Password must have at least %d characters", config.GetPasswordConfig().MinPasswordLen),
}

var upperLowerError = passwordError{
	message: "Password must have both lower and upper case letters",
}

var specialCharactersError = passwordError{
	message: "Password must include at least 1 special character",
}

var numbersError = passwordError{
	message: "Password must include at least one number",
}

type PasswordErrorMap struct {
	MinLen            passwordError
	UpperLower        passwordError
	SpecialCharacters passwordError
	Numbers           passwordError
}

var PasswordErrors = PasswordErrorMap{
	MinLen:            minLenError,
	SpecialCharacters: specialCharactersError,
	Numbers:           numbersError,
	UpperLower:        upperLowerError,
}

func IsPasswordValid(password string) []PasswordError {
	errors := make([]PasswordError, 0)

	if len(password) < config.GetPasswordConfig().MinPasswordLen {
		errors = append(errors, PasswordErrors.MinLen)
	}

	if config.GetPasswordConfig().ShouldHaveNumbers && !strings.ContainsAny(password, numbers) {
		errors = append(errors, PasswordErrors.Numbers)
	}

	if config.GetPasswordConfig().ShouldHaveSpecialChars && !strings.ContainsAny(password, specials) {
		errors = append(errors, PasswordErrors.SpecialCharacters)
	}

	if config.GetPasswordConfig().ShouldBeUpperAndLower {
		if strings.ToLower(password) == password || strings.ToUpper(password) == password {
			errors = append(errors, PasswordErrors.SpecialCharacters)
		}
	}

	return errors
}
