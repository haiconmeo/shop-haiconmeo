package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Fullname string `json:fullname gorm:"column:fullname;"`
	Email    string `json:email gorm:"column:email"`
	Password string `json:password gorm:"column:password"`
}
type Claims struct {
	Email string `json:"username"`
	jwt.RegisteredClaims
}

var sampleSecretKey = []byte("SecretYouShouldHide")

func (user *User) hashPassword(password string) error {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return err
	}
	user.Password = string(bytes)
	return nil
}
func (user *User) CheckPassword(providedPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(providedPassword))
	if err != nil {
		return err
	}
	return nil
}
func authorize(r *http.Request) (string, error) {
	c, err := r.Cookie("token")
	if err != nil {
		return "", err
	}
	tknStr := c.Value
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return sampleSecretKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return "", err
		}
		return "", err
	}
	if !tkn.Valid {
		return "", err
	}
	return claims.Email, nil
}
func login(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			t, err := template.ParseFiles("./template/login.html")
			if err != nil {
				log.Fatal("lỗi ")
			}
			t.Execute(w, nil)

		} else {
			r.ParseForm()
			email := r.FormValue("email")
			var user User
			db.Where("email = ?", email).First(&user)
			err := user.CheckPassword(r.FormValue("password"))
			if err != nil {
				fmt.Fprintf(w, "error")
			} else {
				expirationTime := time.Now().Add(50 * time.Minute)
				claims := &Claims{
					Email: user.Email,
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(expirationTime),
					},
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				tokenString, err := token.SignedString(sampleSecretKey)
				if err != nil {
					fmt.Println(err)
					fmt.Fprintf(w, "error create token")
				}

				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				http.SetCookie(w, &http.Cookie{
					Name:    "token",
					Value:   tokenString,
					Expires: expirationTime,
					Path:    "/",
				})
				http.Redirect(w, r, "/", http.StatusFound)

			}
		}
	}
}
func register(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("method", r.Method)
		if r.Method == "GET" {
			t, err := template.ParseFiles("./template/register.html")
			if err != nil {
				log.Fatal("lỗi ")
			}
			t.Execute(w, nil)

		} else {
			r.ParseForm()
			user := User{
				Fullname: r.FormValue("fullname"),
				Email:    r.FormValue("email"),
			}
			user.hashPassword(r.FormValue("password"))
			db.Create(&user)
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	}
}
func index(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("template/index.html")
	if err != nil {
		fmt.Fprintf(w, "Error Template")
	}
	t.Execute(w, nil)
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})
	mux := mux.NewRouter()

	mux.PathPrefix("/assets/").Handler(http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))))
	mux.HandleFunc("/", index)
	mux.HandleFunc("/login", login(db))
	mux.HandleFunc("/register", register(db))
	http.ListenAndServe(":8080", mux)
}
