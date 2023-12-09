package main

import (
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

func topHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello World"))
}

func secretHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Secret Message"))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// リクエストボディからパスワードを取得
	password := r.FormValue("password")
	if password == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("パスワードが入力されていません"))
		return
	}

	// パスワードを検証
	err := bcrypt.CompareHashAndPassword([]byte(HashedPassword), []byte(password))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("パスワードが間違っています"))
		return
	}

	// JWT を生成
	token := jwt.New(jwt.SigningMethodHS256)
	tokenString, err := token.SignedString([]byte(JWTSecret))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("トークンの生成に失敗しました"))
		return
	}

	// JWT をレスポンスボディに書き込む
	w.Write([]byte(tokenString))
}
