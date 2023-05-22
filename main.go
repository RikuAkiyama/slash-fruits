package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/go-sql-driver/mysql"
)

// DB接続用のグローバル変数
var db *sql.DB

// JWT生成の秘密鍵を保持する変数
var jwtKey = []byte(os.Getenv("JWT_KEY"))

// ユーザー情報を表す構造体
type User struct {
	UserID   int64  `json:"userid"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// スコア提出情報を表す構造体
type ScoreSubmission struct {
	Score int `json:"score"`
}

func main() {
	// 環境変数からDB接続情報を取得
	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASS")
	dbName := os.Getenv("DB_NAME")
	instanceConnectionName := os.Getenv("INSTANCE_CONNECTION_NAME")

	// DSNを作成
	dsn := fmt.Sprintf("%s:%s@unix(/cloudsql/%s)/%s", dbUser, dbPass, instanceConnectionName, dbName)

	var err error
	// DBに接続
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("Database connection failed: %v", err)
		return
	}

	// JWT_KEYのチェック
	if len(jwtKey) == 0 {
		log.Printf("JWT Key is not set")
		return
	}

	// 各種ハンドラを登録
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/tokenRefresh", tokenRefresh)
	http.HandleFunc("/score", scoreHandler)
	http.HandleFunc("/ranking", rankingHandler)
	http.HandleFunc("/userRanking", userRankingHandler)

	// ポート番号を取得。環境変数が設定されていなければ8080を使用
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("defaulting to port %s", port)
	}

	log.Printf("listening on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

// 新規ユーザーを登録
func registerHandler(w http.ResponseWriter, r *http.Request) {
	// POSTメソッドのみ許可
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	var u User
	// リクエストボディからユーザー情報を取得
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// ユーザー名の重複確認
	row := db.QueryRow("SELECT 1 FROM Users WHERE Username = ?", u.Username)
	var exists bool
	err = row.Scan(&exists)
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	} else if exists {
		http.Error(w, "Username already exists", http.StatusBadRequest)
		return
	}

	// パスワードをハッシュ化
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// ユーザーをDBに追加
	result, err := db.Exec("INSERT INTO Users (Username, HashedPassword) VALUES (?, ?)", u.Username, hashedPassword)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 新たに生成したユーザーIDを取得
	userID, err := result.LastInsertId()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// JWTを生成
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userid":   userID,
		"username": u.Username,
		"exp":      time.Now().Add(time.Minute * 10).Unix(),
	})
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// JWTをJSON形式で返す
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// ログイン認証
func loginHandler(w http.ResponseWriter, r *http.Request) {
	// GETメソッドのみ許可
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	var u User
	// リクエストボディからユーザー情報を取得
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// DBからユーザーのIDとハッシュ化されたパスワードを取得
	var userID int
	var hashedPassword string
	err = db.QueryRow("SELECT ID, HashedPassword FROM Users WHERE Username = ?", u.Username).Scan(&userID, &hashedPassword)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// ハッシュ化されたパスワードと入力されたパスワードを比較
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(u.Password))
	if err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// JWTを生成
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userid":   userID,
		"username": u.Username,
		"exp":      time.Now().Add(time.Minute * 10).Unix(),
	})
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// JWTをJSON形式でクライアントへ返す
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// JWTの有効期限をリセット
func tokenRefresh(w http.ResponseWriter, r *http.Request) {
	// GETメソッドのみ許可
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	// JWTからユーザーIDとユーザー名を取得
	tokenStr := r.Header.Get("Authorization")
	claims := &jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	userID := int64((*claims)["userid"].(float64))
	username := (*claims)["username"].(string)

	// JWTの有効期限を確認
	exp, ok := (*claims)["exp"].(float64)
	if !ok || time.Unix(int64(exp), 0).Before(time.Now()) {
		http.Error(w, "Token expired", http.StatusUnauthorized)
		return
	}

	// JWTをリフレッシュ
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userid":   userID,
		"username": username,
		"exp":      time.Now().Add(time.Minute * 10).Unix(),
	})
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// JWTをJSON形式でクライアントへ返す
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// スコアを登録
func scoreHandler(w http.ResponseWriter, r *http.Request) {
	// POSTメソッドのみ許可
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	// JWTからユーザーIDを取得
	tokenStr := r.Header.Get("Authorization")
	claims := &jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {

		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	userID := int64((*claims)["userid"].(float64))

	// リクエストボディからスコアを読み込む
	var submission ScoreSubmission
	err = json.NewDecoder(r.Body).Decode(&submission)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// データベースに新たなスコアを登録
	_, err = db.Exec("INSERT INTO Scores (UserID, GameScore) VALUES (?, ?)", userID, submission.Score)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 成功した場合、200ステータスコードとともにJSONをクライアントに返す
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// 全体のスコアランキングを取得
func rankingHandler(w http.ResponseWriter, r *http.Request) {
	// GETメソッドのみ許可
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	// 全プレイ履歴の中から、スコアが高い順に5件までIDとユーザー名とスコアIDとスコアを取得
	rows, err := db.Query(`
		SELECT Users.ID, Users.Username, Scores.ScoreID, Scores.GameScore
		FROM Users
		JOIN Scores ON Users.ID = Scores.UserID
		ORDER BY Scores.GameScore DESC, Scores.Timestamp ASC
		LIMIT 5
	`)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// レスポンスの形式を定義
	type Response struct {
		UserID   int64  `json:"user_id"`
		Username string `json:"username"`
		ScoreID  int64  `json:"score_id"`
		Score    int    `json:"score"`
	}

	// データベースからの結果を格納します
	var ranking []Response
	for rows.Next() {
		var r Response
		if err := rows.Scan(&r.UserID, &r.Username, &r.ScoreID, &r.Score); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		ranking = append(ranking, r)
	}

	// エラーハンドリング
	if err := rows.Err(); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 結果をJSONとしてクライアントに返す
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ranking)
}

// ユーザー個別のスコアランキングを取得
func userRankingHandler(w http.ResponseWriter, r *http.Request) {
	// GETメソッドのみ許可
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	// JWTからユーザーIDを取得
	tokenStr := r.Header.Get("Authorization")
	claims := &jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	userID := int64((*claims)["userid"].(float64))

	// ユーザーの全プレイ履歴の中から、スコアが高い順に5件までIDとユーザー名とスコアIDとスコアを取得
	rows, err := db.Query(`
		SELECT Users.ID, Users.Username, Scores.ScoreID, Scores.GameScore
		FROM Users
		JOIN Scores ON Users.ID = Scores.UserID
		WHERE Users.ID = ?
		ORDER BY Scores.GameScore DESC, Scores.Timestamp ASC
		LIMIT 5
	`, userID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// レスポンスの形式を定義
	type Response struct {
		UserID   int64  `json:"user_id"`
		Username string `json:"username"`
		ScoreID  int64  `json:"score_id"`
		Score    int    `json:"score"`
	}

	// データベースからの結果を格納します
	var ranking []Response
	for rows.Next() {
		var r Response
		if err := rows.Scan(&r.UserID, &r.Username, &r.ScoreID, &r.Score); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		ranking = append(ranking, r)
	}

	// エラーハンドリング
	if err := rows.Err(); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 結果をJSONとしてクライアントに返す
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ranking)
}
