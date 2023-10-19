package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
)

type PageData struct {
	Title   string
	Message string
}

var sessions = make(map[string]SessionData)

type SessionData struct {
	Username string
}

var sessionID string
var userDB = map[string]string{
	"user":  "user",
	"user2": "user123",
}

func generateUniqueSessionID() string {
	// Create a random byte slice
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return ""
	}

	// Encode the random bytes to base64
	sessionID := base64.StdEncoding.EncodeToString(randomBytes)
	return sessionID
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")

	if sessionID != "" {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	}
	data := struct {
		Username string
		Password string
		ImageUrl string
	}{
		Username: "",

		Password: "",
		ImageUrl: "images/user.png",
	}
	tmpl, err := template.ParseFiles("index.html")
	if err != nil {
		panic(err)
	}
	if r.Method != http.MethodPost {

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	storedPassword, ok := userDB[username]

	if !ok {

		data.Username = "invalid username"

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		return
	}
	if storedPassword != password {
		data.Password = "Wrong password"

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		return

	}

	sessionID = generateUniqueSessionID()

	sessions[sessionID] = SessionData{
		Username: username,
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "session-name",
		Value: sessionID,

		HttpOnly: true,
	})
	http.Redirect(w, r, "/home", http.StatusSeeOther)
}

func homePage(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	if sessionID == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	http.ServeFile(w, r, "home.html")
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("session-name")
	if err != nil {

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	sessionID = cookie.Value

	delete(sessions, sessionID)
	sessionID = ""

	http.SetCookie(w, &http.Cookie{
		Name:     "session-name",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {

	fs := http.FileServer(http.Dir("images"))
	http.Handle("/images/", http.StripPrefix("/images/", fs))

	http.HandleFunc("/", loginHandler)
	http.HandleFunc("/home", homePage)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("Error:", err)
	}
}
