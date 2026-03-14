package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"message":"test-backend ok"}`)
	})

	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, `{"query":"%s","results":[]}`, q)
	})

	mux.HandleFunc("/page", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		fmt.Fprintf(w, `{"page":"%s"}`, path)
	})

	mux.HandleFunc("/exec", func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		fmt.Fprintf(w, `{"cmd":"%s"}`, cmd)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	log.Println("test-backend starting on :9000")
	if err := http.ListenAndServe(":9000", mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
