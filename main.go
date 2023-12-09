package main

import (
	"log"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
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