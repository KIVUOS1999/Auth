package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/KIVUOS1999/Auth/constants"
	"github.com/KIVUOS1999/Auth/models"
	"github.com/KIVUOS1999/Auth/store"
	"github.com/golang-jwt/jwt"
)

type handler struct {
}

type IHandler interface {
	Login(w http.ResponseWriter, r *http.Request)
	Validate(w http.ResponseWriter, r *http.Request)
}

func New() IHandler {
	return &handler{}
}

func (h *handler) Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "applicaion/json")

	log.Println("Inside login")

	requestPayload := models.TokenRequest{}

	err := json.NewDecoder(r.Body).Decode(&requestPayload)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	if store.UsersData[requestPayload.ID] != requestPayload.Secret {
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(models.CustomError{
			Reason: "wrong username password combination",
		})

		return
	}

	expirationTime := time.Now().UTC().Add(2 * time.Minute)
	claims := models.Claims{
		GrantType: requestPayload.GrantType,
		Scope:     requestPayload.Scope,
		StandardClaims: jwt.StandardClaims{
			Subject:   requestPayload.ID,
			ExpiresAt: expirationTime.Unix(),
			Audience:  requestPayload.Audience,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString([]byte(constants.JWT_SECRET))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(models.CustomError{
			Reason: "signed token error: " + err.Error(),
		})

		return
	}

	json.NewEncoder(w).Encode(models.TokenResponse{
		Auth: signedToken,
	})
}

func (h *handler) Validate(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	log.Println("Inside validate")

	validateReq := models.ValidateRequest{}

	err := json.NewDecoder(r.Body).Decode(&validateReq)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.CustomError{
			Reason: err.Error(),
		})

		return
	}

	claims := models.Claims{}

	token, err := jwt.ParseWithClaims(validateReq.Auth, &claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(constants.JWT_SECRET), nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(models.CustomError{
				Reason: "Signature Invalid",
			})

			return
		}

		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.CustomError{
			Reason: err.Error(),
		})

		return
	}

	if claims.ExpiresAt <= time.Now().UTC().Unix() {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(models.CustomError{
			Reason: "Token has expired",
		})
	}

	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}
}
