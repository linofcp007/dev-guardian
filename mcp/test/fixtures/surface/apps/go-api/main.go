package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	mux := http.NewServeMux()

	http.HandleFunc("/go/health", health)
	mux.HandleFunc("/go/orders", orders)

	log.Fatal(http.ListenAndServe(addr, mux))
}

func health(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func orders(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
