package dto

type Log struct {
	ClientEncryptedStackTrace string `json:"stackTrace"`
}

type DecryptedLog struct {
	StackTrace string `json:"stackTrace"`
}
