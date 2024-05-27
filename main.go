package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var tmpl = template.Must(template.ParseFiles("login.html", "signup.html"))

func main() {
	fmt.Println("Starting application...")
	db, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	fmt.Println("Database connected successfully.")

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		loginHandler(w, r, db)
	})
	http.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		signUpHandler(w, r, db)
	})

	http.Handle("/", http.FileServer(http.Dir("./")))

	fmt.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func loginHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodPost {
		tmpl.Execute(w, nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var storedHash string
	err := db.QueryRow("SELECT pasword FROM users WHERE user name = ?", username).Scan(&storedHash)
	if err != nil {
		http.Error(w, "Invalid Username Or password.", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	if err != nil {
		http.Error(w, "Invalid username or password.", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "Login successfull Welcome, %s", username)
}

func signUpHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodPost {
		tmpl.Execute(w, nil)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Server error, unable to create your account", http.StatusInternalServerError)
		return
	}
	_, err = db.Exec("INSERT INTO users (username, Password) VALUES (?, ?)", username, hashedPassword)
	if err != nil {
		http.Error(w, "Username  already taken.", http.StatusConflict)
		return
	}
	fmt.Fprintf(w, "Sign up successful! Welcome, %s.", username)
}
