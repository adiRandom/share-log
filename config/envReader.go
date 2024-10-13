package config

import (
	"os"
	"strconv"
)

func getEnvInt(key string, defValue int) int {
	strVal := os.Getenv(key)
	intVal, err := strconv.ParseInt(strVal, 10, 64)
	if err != nil {
		return defValue
	}

	return int(intVal)
}

func getEnvBool(key string, defValue bool) bool {
	strVal := os.Getenv(key)
	boolVal, err := strconv.ParseBool(strVal)
	if err != nil {
		return defValue
	}

	return boolVal
}

func GetPasswordConfig() PasswordConfig {
	return PasswordConfig{
		MinPasswordLen:         getEnvInt(passwordConfigMinPasswordLen, defaultPasswordMinLen),
		ShouldBeUpperAndLower:  getEnvBool(passwordConfigUpperLowerPasswordRule, defaultPasswordUpperLower),
		ShouldHaveNumbers:      getEnvBool(passwordConfigMNumbersPasswordRule, defaultPasswordHasNumber),
		ShouldHaveSpecialChars: getEnvBool(passwordConfigSpecialCharPasswordRule, defaultPasswordSpecialChars),
	}
}

func GetKeyPaths() KeysPathsConfig {
	return KeysPathsConfig{
		JwePkPath:     os.Getenv(jwePkPath),
		JwePubKeyPath: os.Getenv(jwePubKeyPath),
		JwtPubKeyPath: os.Getenv(jwtPubKeyPath),
		JwtPkPath:     os.Getenv(jwtPkPath),
	}
}

func GetSecrets() SecretsConfig {
	return SecretsConfig{
		LogSharingSecret: os.Getenv(logSharingSecret),
	}
}
