package main

import (
	"net/http"

	"github.com/KIVUOS1999/Auth/handler"
	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	h := handler.New()

	r.HandleFunc("/oauth", h.Login)
	r.HandleFunc("/validate", h.Validate)

	http.ListenAndServe(":8000", r)
}
