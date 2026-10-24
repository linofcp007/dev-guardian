// Deliberately vulnerable: the gosec e2e fixture (test/e2e/gosecSast.test.ts).
package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	rows, _ := db.Query("SELECT * FROM users WHERE id=" + id)
	fmt.Fprintln(w, rows)
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("sh", "-c", "ping "+host).Output()
	_, _ = w.Write(out)
	sum := md5.Sum([]byte(id)) // #nosec G401 -- fixture: a suppressed finding
	_ = sum
}

func main() {
	http.HandleFunc("/", handler)
	_ = http.ListenAndServe(":8080", nil)
}
