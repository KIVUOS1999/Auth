package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/KIVUOS1999/Auth/constants"
	"github.com/KIVUOS1999/Auth/models"
	"github.com/KIVUOS1999/Auth/store"
	"github.com/KIVUOS1999/easyLogs/pkg/log"
	"github.com/golang-jwt/jwt"
)

const (
	accessTokenExpire  = 2
	refreshTokenExpire = 60

	gtyAccessToken  = "auth_token"
	gtyRefreshToken = "refresh_token"
)

type handler struct{}

type IHandler interface {
	Login(w http.ResponseWriter, r *http.Request)
	RefreshToken(w http.ResponseWriter, r *http.Request)
	Validate(w http.ResponseWriter, r *http.Request)
}

func New() IHandler {
	return &handler{}
}

func (h *handler) generateRefreshToken(id string) (*string, error) {
	log.Info("Inside generateRefreshToken")

	expirationTime := time.Now().UTC().Add(refreshTokenExpire * time.Minute)

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
	})

	signedRefreshToken, err := refreshToken.SignedString([]byte(constants.JWT_SECRET))
	if err != nil {
		log.Error("Error while signing refresh token", err.Error())

		return nil, err
	}

	h.storeRefreshTokens(signedRefreshToken, id)

	return &signedRefreshToken, nil
}

func (h *handler) generateAccessToken(requestPayload *models.TokenRequest) (*string, error) {
	expirationTime := time.Now().UTC().Add(accessTokenExpire * time.Minute)
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
		return nil, err
	}

	return &signedToken, nil
}

func (h *handler) storeRefreshTokens(refreshToken, id string) {
	store.RefreshTable[refreshToken] = id
}

func (h *handler) validateAndGetRefreshToken(refreshToken, id string) bool {
	if retrivedID, ok := store.RefreshTable[refreshToken]; ok {
		if retrivedID != id {
			log.Error("id not present in db")

			return false
		}
	}

	claims, err := h.parseToken(refreshToken)
	if err != nil {
		log.Error("refresh token parse token failed")

		return false
	}

	if claims.ExpiresAt <= time.Now().UTC().Unix() {
		log.Error("refresh token expired")

		return false
	}

	return true
}

func (h *handler) Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "applicaion/json")

	log.Info("Inside login")

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

	accessToken, err := h.generateAccessToken(&requestPayload)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(models.CustomError{
			Reason: "signed token error: " + err.Error(),
		})

		return
	}

	refreshToken, err := h.generateRefreshToken(requestPayload.ID)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(models.CustomError{
			Reason: "refresh generation error: " + err.Error(),
		})

		return
	}

	json.NewEncoder(w).Encode(models.TokenResponse{
		Auth:    *accessToken,
		Refresh: *refreshToken,
	})
}

func (h *handler) Validate(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	log.Info("Inside validate")

	validateReq := models.ValidateRequest{}

	err := json.NewDecoder(r.Body).Decode(&validateReq)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.CustomError{
			Reason: err.Error(),
		})

		return
	}

	claims, err := h.parseToken(validateReq.Auth)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
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
}

func (h *handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")

	refreshReq := models.TokenResponse{}
	err := json.NewDecoder(r.Body).Decode(&refreshReq)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	accessToken := refreshReq.Auth

	claims, _ := h.parseToken(accessToken)
	if claims == nil || claims.Subject == "" {
		log.Error("Auth claims not parsed")

		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(models.CustomError{
			Reason: "auth claims not parsed",
		})

		return
	}

	id := claims.Subject

	if isValidRefreshToken := h.validateAndGetRefreshToken(refreshReq.Refresh, id); !isValidRefreshToken {
		log.Error("refresh token validation failed")

		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(models.CustomError{
			Reason: "failed in refresh token validation stage",
		})

		return
	}

	log.Debug("Refresh token valid.")

	tokenRequestPayload := models.TokenRequest{
		ID:        id,
		GrantType: gtyRefreshToken,
		Scope:     claims.Scope,
		Audience:  claims.Audience,
	}

	generatedAccessToken, err := h.generateAccessToken(&tokenRequestPayload)
	if err != nil {
		log.Error("Access token generation failed")

		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.CustomError{
			Reason: err.Error(),
		})

		return
	}

	generatedRefreshToken, err := h.generateRefreshToken(id)
	if err != nil {
		log.Error("Refresh token generation failed")

		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.CustomError{
			Reason: err.Error(),
		})

		return
	}

	resp := models.TokenResponse{
		Auth:    *generatedAccessToken,
		Refresh: *generatedRefreshToken,
	}

	json.NewEncoder(w).Encode(resp)
}

func (h *handler) parseToken(jwtToken string) (*models.Claims, error) {
	claims := models.Claims{}

	token, err := jwt.ParseWithClaims(jwtToken, &claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(constants.JWT_SECRET), nil
	})
	if err != nil {
		log.Error("Error while parsing token", err.Error())
		return &claims, err

	}

	if !token.Valid {
		log.Error("token not valid")

		return &claims, errors.New("token not valid")
	}

	return &claims, nil
}
