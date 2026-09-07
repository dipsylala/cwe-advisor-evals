//go:build tools

// Keeps every superset module referenced so `go mod tidy` does not drop them from go.mod.
package tools

import (
	_ "github.com/golang-jwt/jwt/v5"
	_ "github.com/gorilla/sessions"
	_ "github.com/jmoiron/sqlx"
	_ "google.golang.org/grpc"
	_ "google.golang.org/grpc/codes"
	_ "google.golang.org/grpc/status"
	_ "golang.org/x/crypto/bcrypt"
	_ "gorm.io/gorm"
)
