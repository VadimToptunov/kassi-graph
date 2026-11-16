package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

// GuardedHandler — calls access check before DB
func GuardedHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	if !CheckAccess(r, userID) {
		http.Error(w, "forbidden", 403)
		return
	}
	db.Exec("UPDATE users SET flag=1 WHERE id=?", userID)
}

// UnguardedHandler — direct DB touch, NO access check
func UnguardedHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	db.Exec("UPDATE users SET flag=1 WHERE id=?", userID)
}

func CheckAccess(r *http.Request, userID string) bool {
	return r.Header.Get("X-Auth") == "ok"
}

func main() {
	http.HandleFunc("/guarded", GuardedHandler)
	http.HandleFunc("/unguarded", UnguardedHandler)
	http.ListenAndServe(":8080", nil)
}
