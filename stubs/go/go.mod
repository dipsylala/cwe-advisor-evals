module evalcases

go 1.25

// Superset module set for type-checking every Go fixture (scripts/compilecheck.py). Case files are
// copied into a package directory under this module and vetted against these requirements.
// tools.go imports every module so `go mod tidy` keeps them.
require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/gorilla/sessions v1.4.0
	github.com/jmoiron/sqlx v1.4.0
	google.golang.org/grpc v1.67.1
	gorm.io/gorm v1.25.12
)

require golang.org/x/crypto v0.26.0

require (
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240814211410-ddb44dafa142 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)
