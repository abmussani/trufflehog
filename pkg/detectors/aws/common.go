package aws

import regexp "github.com/wasilibs/go-re2"

const (
	RequiredIdEntropy     = 3.0
	RequiredSecretEntropy = 4.25
)

var SecretPat = regexp.MustCompile(`(?:[^A-Za-z0-9+/]|\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\z)`)
