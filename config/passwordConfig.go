package config

type PasswordConfig struct {
	MinPasswordLen         int
	ShouldHaveSpecialChars bool
	ShouldHaveNumbers      bool
	ShouldBeUpperAndLower  bool
}

const defaultPasswordMinLen = 8
const defaultPasswordSpecialChars = true
const defaultPasswordHasNumber = true
const defaultPasswordUpperLower = true
