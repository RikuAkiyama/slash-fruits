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

// エラーレスポンス用の構造体
type ErrorResponse struct {
	Message string `json:"message"`
}

// エラーレスポンスを返却
func errorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{Message: message})
}

// 正規のレスポンスを返却
func jsonResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
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
		errorResponse(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	var u User
	// リクエストボディからユーザー情報を取得
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		errorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// ユーザー名の重複確認
	row := db.QueryRow("SELECT 1 FROM Users WHERE Username = ?", u.Username)
	var exists bool
	err = row.Scan(&exists)
	if err != nil && err != sql.ErrNoRows {
		errorResponse(w, "Database error", http.StatusInternalServerError)
		return
	} else if exists {
		errorResponse(w, "Username already exists", http.StatusBadRequest)
		return
	}

	// パスワードをハッシュ化
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		errorResponse(w, "Password hashing error", http.StatusInternalServerError)
		return
	}

	// ユーザーをDBに追加
	result, err := db.Exec("INSERT INTO Users (Username, HashedPassword) VALUES (?, ?)", u.Username, hashedPassword)
	if err != nil {
		errorResponse(w, "Database error", http.StatusInternalServerError)
		return
	}

	// 新たに生成したユーザーIDを取得
	userID, err := result.LastInsertId()
	if err != nil {
		errorResponse(w, "Database error", http.StatusInternalServerError)
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
		errorResponse(w, "Token generation error", http.StatusInternalServerError)
		return
	}

	// JWTをJSON形式でクライアントへ送信
	response := map[string]string{"token": tokenString}
	jsonResponse(w, response, http.StatusOK)
}

// ログイン認証
func loginHandler(w http.ResponseWriter, r *http.Request) {
	// POSTメソッドのみ許可
	if r.Method != http.MethodPost {
		errorResponse(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	var u User
	// リクエストボディからユーザー情報を取得
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		errorResponse(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// DBからユーザーのIDとハッシュ化されたパスワードを取得
	var userID int
	var hashedPassword string
	err = db.QueryRow("SELECT ID, HashedPassword FROM Users WHERE Username = ?", u.Username).Scan(&userID, &hashedPassword)
	if err != nil {
		errorResponse(w, "User not found", http.StatusNotFound)
		return
	}

	// ハッシュ化されたパスワードと入力されたパスワードを比較
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(u.Password))
	if err != nil {
		errorResponse(w, "Invalid password", http.StatusUnauthorized)
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
		errorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// JWTをJSON形式でクライアントへ送信
	response := map[string]string{"token": tokenString}
	jsonResponse(w, response, http.StatusOK)
}

// JWTの有効期限をリセット
func tokenRefresh(w http.ResponseWriter, r *http.Request) {
	// GETメソッドのみ許可
	if r.Method != http.MethodGet {
		errorResponse(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	// ヘッダーからJWTを取得し、クレームにデコード
	tokenStr := r.Header.Get("Authorization")
	claims := &jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		errorResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// JWTからユーザーIDとユーザー名を取得
	userID := int64((*claims)["userid"].(float64))
	username := (*claims)["username"].(string)

	// JWTの有効期限を確認
	exp, ok := (*claims)["exp"].(float64)
	if !ok || time.Unix(int64(exp), 0).Before(time.Now()) {
		errorResponse(w, "Token expired", http.StatusUnauthorized)
		return
	}

	// JWTを新しく生成
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userid":   userID,
		"username": username,
		"exp":      time.Now().Add(time.Minute * 10).Unix(),
	})
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		errorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 生成したJWTをクライアントに送信
	response := map[string]string{"token": tokenString}
	jsonResponse(w, response, http.StatusOK)
}

// スコアを登録
func scoreHandler(w http.ResponseWriter, r *http.Request) {
	// POSTメソッドのみ許可
	if r.Method != http.MethodPost {
		errorResponse(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	// ヘッダーからJWTを取得し、クレームにデコード
	tokenStr := r.Header.Get("Authorization")
	claims := &jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		errorResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// JWTからユーザーIDを取得
	userID := int64((*claims)["userid"].(float64))

	// リクエストボディからスコアを読み込む
	var submission ScoreSubmission
	err = json.NewDecoder(r.Body).Decode(&submission)
	if err != nil {
		errorResponse(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// データベースに新たなスコアを登録
	_, err = db.Exec("INSERT INTO Scores (UserID, GameScore) VALUES (?, ?)", userID, submission.Score)
	if err != nil {
		errorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 成功した場合、JSONをクライアントに送信
	responce := map[string]string{"status": "success"}
	jsonResponse(w, responce, http.StatusOK)
}

// 全体のスコアランキングを取得
func rankingHandler(w http.ResponseWriter, r *http.Request) {
	// GETメソッドのみ許可
	if r.Method != http.MethodGet {
		errorResponse(w, "Invalid method", http.StatusMethodNotAllowed)
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
		errorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// レスポンスの形式を定義
	type Response struct {
		UserID   int64  `json:"user_id"`
		Username string `json:"username"`
		ScoreID  int64  `json:"score_id"`
		Score    int64  `json:"score"`
	}

	// データベースからの結果を格納
	var ranking []Response
	for rows.Next() {
		var r Response
		if err := rows.Scan(&r.UserID, &r.Username, &r.ScoreID, &r.Score); err != nil {
			errorResponse(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		ranking = append(ranking, r)
	}
	if err := rows.Err(); err != nil {
		errorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 結果をJSONとしてクライアントに送信
	jsonResponse(w, ranking, http.StatusOK)
}

// ユーザー個別のスコアランキングを取得
func userRankingHandler(w http.ResponseWriter, r *http.Request) {
	// GETメソッドのみ許可
	if r.Method != http.MethodGet {
		errorResponse(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	// ヘッダーからJWTを取得し、クレームにデコード
	tokenStr := r.Header.Get("Authorization")
	claims := &jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		errorResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// JWTからユーザーIDを取得
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
		errorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// レスポンスの形式を定義
	type Response struct {
		UserID   int64  `json:"user_id"`
		Username string `json:"username"`
		ScoreID  int64  `json:"score_id"`
		Score    int64  `json:"score"`
	}

	// データベースからの結果を格納
	var ranking []Response
	for rows.Next() {
		var r Response
		if err := rows.Scan(&r.UserID, &r.Username, &r.ScoreID, &r.Score); err != nil {
			errorResponse(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		ranking = append(ranking, r)
	}
	if err := rows.Err(); err != nil {
		errorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 結果をJSONとしてクライアントに送信
	jsonResponse(w, ranking, http.StatusOK)
}
