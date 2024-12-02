package main

import (
	"net/http"

	"github.com/KIVUOS1999/Auth/handler"
	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	h := handler.New()

	r.HandleFunc("/oauth", h.Login).Methods(http.MethodPost)
	r.HandleFunc("/refresh", h.RefreshToken).Methods(http.MethodPost)
	r.HandleFunc("/validate", h.Validate).Methods(http.MethodPost)

	http.ListenAndServe(":8000", r)
}
