package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/justinas/alice"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"time"
)

type App struct {
	DB     *sql.DB
	JWTKey []byte
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password, omitempty"`
}

type Claims struct {
	Username string `json:"username"`
	XataID   string `json:"xata_id"`
	jwt.RegisteredClaims
}

type UserResponse struct {
	XataID   string `json:"xata_id"`
	Username string `json:"username"`
	Token    string `json:"token"`
}
type ErrorResponse struct {
	Message string `json:"message"`
}
type RouterResponse struct {
	Message string `json:"message"`
	ID      string `json:"id,omitempty"`
}

func main() {
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	connectionString := os.Getenv("XATA_PSQL_URL")

	if len(connectionString) == 0 {
		log.Fatalf("Error connecting to PostgreSQL")
	}

	DB, err := sql.Open("postgres", connectionString)
	if err != nil {
		log.Fatal(err)
	}
	defer DB.Close()

	app := &App{DB: DB}

	router := mux.NewRouter()

	router.Handle("/register", alice.New(logginMiddleware).ThenFunc(app.register)).Methods("POST")
	router.Handle("/login", alice.New(logginMiddleware).ThenFunc(app.login)).Methods("POST")
	router.Handle("/", alice.New(logginMiddleware).ThenFunc(getProjects)).Methods("GET")
	router.Handle("/", alice.New(logginMiddleware).ThenFunc(createProject)).Methods("POST")
	router.Handle("/{id}", alice.New(logginMiddleware).ThenFunc(getProject)).Methods("GET")
	router.Handle("/{id}", alice.New(logginMiddleware).ThenFunc(updateProject)).Methods("PUT")
	router.Handle("/delete/:id", alice.New(logginMiddleware).ThenFunc(deleteProject)).Methods("DELETE")

	log.Fatal(http.ListenAndServe(":5000", router))
}

func logginMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}

func responseWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{message})
}

// register

func (app *App) register(w http.ResponseWriter, r *http.Request) {
	var cred Credentials
	err := json.NewDecoder(r.Body).Decode(&cred)

	if err != nil {
		responseWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cred.Password), bcrypt.DefaultCost)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "Error hashing password")
		return
	}

	var xataId string
	err = app.DB.QueryRow("INSERT INTO \"users\" (username, password) VALUES ($1, $2) RETURNING xata_id", cred.Username, string(hashedPassword)).Scan(&xataId)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "Error creating user")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{XataID: xataId, Username: cred.Username})
}

func (app *App) generateToken(username string, xataID string) (string, error) {
	expirationTime := time.Now().Add(5 * time.Minute)

	claims := &Claims{Username: username, XataID: xataID, RegisteredClaims: jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expirationTime),
	}}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString("")

	fmt.Printf("%v", app)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// lgoin
func (app *App) login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		responseWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	var storedCreds Credentials
	var xataID string

	err = app.DB.QueryRow("SELECT xata_id, username, password FROM \"users\" WHERE useraname=$1", creds.Username).Scan(&xataID, &storedCreds.Username)
	if err != nil {
		if err == sql.ErrNoRows {
			responseWithError(w, http.StatusUnauthorized, "User not found")
			return
		}
		responseWithError(w, http.StatusInternalServerError, "Invalid request payload")
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(creds.Password))

	if err != nil {
		responseWithError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	tokenString, err := app.generateToken(creds.Username, xataID)

	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "Error generating token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{
		XataID:   xataID,
		Username: creds.Username,
		Token:    tokenString,
	})
}

// create Project
func createProject(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(RouterResponse{Message: "Hello World"})
}

// update project
func updateProject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(RouterResponse{Message: "Hello World"})
}

// getProjects
func getProjects(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(RouterResponse{Message: "Hello World"})
}

// getProject
func getProject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(RouterResponse{Message: "Hello World"})
}

// deleteProject
func deleteProject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(RouterResponse{Message: "Hello World"})
}
