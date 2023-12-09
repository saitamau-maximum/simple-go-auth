package main

import (
	"log"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var (
	HashedPassword string
	JWTSecret      string
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(".env ファイルの読み込みに失敗しました")
	}
	HashedPassword = os.Getenv("HASHED_PASSWORD")
	JWTSecret = os.Getenv("JWT_SECRET")
	if HashedPassword == "" {
		log.Fatal("HASHED_PASSWORD が環境変数に設定されていません")
	}
	if JWTSecret == "" {
		log.Fatal("JWT_SECRET が環境変数に設定されていません")
	}
	http.HandleFunc("/", topHandler)
	http.Handle("/secret", authMiddleware(http.HandlerFunc(secretHandler)))
	http.HandleFunc("/login", loginHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Authorization ヘッダーからトークンを取得
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("トークンがありません"))
			return
		}

		// トークンを検証
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return []byte(JWTSecret), nil
		})
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("トークンの検証に失敗しました"))
			return
		}

		// トークンが有効期限切れかどうかを検証
		if !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("トークンが有効期限切れです"))
			return
		}

		// 次のハンドラを呼び出す
		next.ServeHTTP(w, r)
	})
}

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
