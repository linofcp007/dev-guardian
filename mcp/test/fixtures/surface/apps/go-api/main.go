package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	// The fixture's one resolvable intra-project Go import: a package
	// DIRECTORY under this module. The path carries the `go-api/` segment
	// because go.mod sits at the tree root (`module example.com/fixture`),
	// which is the layout resolveGo's suffix match assumes — see its doc
	// comment. See go-api/pkg/util/shout.go.
	"example.com/fixture/go-api/pkg/util"
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
	w.Header().Set("X-Origin", util.Shout("go-api"))
	w.WriteHeader(http.StatusNoContent)
}
