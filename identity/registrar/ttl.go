package main

import (
	"fmt"
	"strconv"
)

// lifetimes are whole seconds. Defaults match the previous fixed registrar
// behavior: a ten-minute join token, a five-minute JWT-SVID, and a one-hour
// X.509-SVID. An already minted join token keeps the expiry stored on its
// Secret; these values apply to the next token and to reconciled entries.
type lifetimes struct {
	joinToken int32
	jwtSvid   int32
	x509Svid  int32
}

func parseTTL(name, raw string) (int32, error) {
	n, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || n < 60 || n > 86400 {
		return 0, fmt.Errorf("%s must be a whole number of seconds from 60 to 86400", name)
	}
	return int32(n), nil
}

func lifetimesFromEnv() (lifetimes, error) {
	join, err := parseTTL("JOIN_TOKEN_TTL", env("JOIN_TOKEN_TTL", "600"))
	if err != nil {
		return lifetimes{}, err
	}
	jwt, err := parseTTL("JWT_SVID_TTL", env("JWT_SVID_TTL", "300"))
	if err != nil {
		return lifetimes{}, err
	}
	x509, err := parseTTL("X509_SVID_TTL", env("X509_SVID_TTL", "3600"))
	if err != nil {
		return lifetimes{}, err
	}
	return lifetimes{joinToken: join, jwtSvid: jwt, x509Svid: x509}, nil
}
