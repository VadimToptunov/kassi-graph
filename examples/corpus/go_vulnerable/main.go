package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

var db *sql.DB

// GuardedRead — authz via CheckAccess before query
func GuardedRead(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	if !CheckAccess(r, userID) {
		http.Error(w, "forbidden", 403)
		return
	}
	db.QueryRow("SELECT email FROM users WHERE id = ?", userID)
	fmt.Fprintln(w, "ok")
}

// UnguardedWrite — direct Exec, no auth check (BUG)
func UnguardedWrite(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	db.Exec("UPDATE users SET flag=1 WHERE id=?", userID)
	fmt.Fprintln(w, "ok")
}

// SafeSelfProfile — no attacker-controlled param, uses session identity via
// GetUserFromContext (adapter sanitizer)
func SafeSelfProfile(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r)
	db.QueryRow("SELECT email FROM users WHERE id = ?", user)
	fmt.Fprintln(w, "ok")
}

// UnguardedExec — classic SQLi + BOLA combo
func UnguardedExec(w http.ResponseWriter, r *http.Request) {
	orderID := r.URL.Query().Get("order")
	db.Exec("DELETE FROM orders WHERE id=" + orderID)
	fmt.Fprintln(w, "ok")
}

func CheckAccess(r *http.Request, userID string) bool {
	return r.Header.Get("X-Auth") == "ok"
}

func GetUserFromContext(r *http.Request) string {
	return r.Context().Value("user").(string)
}

func main() {
	http.HandleFunc("/read", GuardedRead)
	http.HandleFunc("/write", UnguardedWrite)
	http.HandleFunc("/me", SafeSelfProfile)
	http.HandleFunc("/order/delete", UnguardedExec)
	http.ListenAndServe(":8080", nil)
}
