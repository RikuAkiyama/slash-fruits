# slash-fruits
## 用途
勉強のために作った自作ゲーム用
ユーザ認証とスコア管理のためのAPI

## APIの仕様
6種類のエンドポイントがあります

| エンドポイント  | 用途                               |
| :------------ | :-------------------------------- |
| /register     | ユーザー登録                        |
| /login        | ログイン認証                        |
| /tokenRefresh | 認証トークンの有効期限リセット         |
| /score        | ゲームのスコア登録                   |
| /ranking      | ユーザ全員のスコアランキングを取得      |
| /userRanking  | ログインユーザのみのスコアランキング取得 |

## 想定しているDB
MySQL 8.0.26

Usersテーブル
| ID                 | Username     | HashedPassword |
| :----------------- | :----------- | :------------- |
| INT AUTO_INCREMENT | VARCHAR(255) | VARCHAR(255)   |
| PRIMARY KEY        |              |                |

Scoresテーブル
| ScoreID            | UserID | GameScore | Timestamp                          | 
| :----------------- | :----- | :-------- | :--------------------------------- |
| INT AUTO_INCREMENT | INT    | INT       | DATETIME DEFAULT CURRENT_TIMESTAMP |
| PRIMARY KEY        |        |           |                                    |

