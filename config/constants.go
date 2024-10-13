package config

const passwordConfigMinPasswordLen = "minPasswordLen"
const passwordConfigUpperLowerPasswordRule = "upperLowerPasswordRule"
const passwordConfigSpecialCharPasswordRule = "specialCharPasswordRule"
const passwordConfigMNumbersPasswordRule = "numbersPasswordRule"

// RSA KEY
const jwePubKeyPath = "jwePubKeyPath"
const jwePkPath = "jwePkPath"

// ECDSA in EC format
// pk is in key format (might be just the ext and underlying is pem, no clue :) )
const jwtPubKeyPath = "jwtPubKeyPath"
const jwtPkPath = "jwtPkPath"

const logSharingSecret = "logSharingSecret"
