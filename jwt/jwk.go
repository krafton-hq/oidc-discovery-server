package jwt

import (
	"time"

	"gopkg.in/square/go-jose.v2"
)

type JsonWebKey struct {
	jose.JSONWebKey

	expires time.Time
}

func NewJsonWebKey(jwk jose.JSONWebKey, expires time.Time) JsonWebKey {
	return JsonWebKey{
		JSONWebKey: jwk,
		expires:    expires,
	}
}

func (key *JsonWebKey) Algorithm() jose.SignatureAlgorithm {
	return jose.SignatureAlgorithm(key.JSONWebKey.Algorithm)
}

func (key *JsonWebKey) Use() string {
	return key.JSONWebKey.Use
}

func (key *JsonWebKey) Key() interface{} {
	return key.JSONWebKey.Key
}

func (key *JsonWebKey) ID() string {
	return key.JSONWebKey.KeyID
}

func (key *JsonWebKey) Expires(time time.Time) bool {
	return key.expires.Before(time)
}
