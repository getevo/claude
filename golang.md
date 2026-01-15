# CLAUDE.md - Golang Project Guidelines

## Framework Stack
- **Backend**: `github.com/getevo/evo/v2` | **ORM**: `gorm.io/gorm` | **REST**: `github.com/getevo/restify` | **DB**: MariaDB

## Claude Rules
- Follow existing patterns even if suboptimal
- Do **not** refactor unless explicitly requested
- Prefer consistency over cleverness
- Ask before introducing new abstractions

## General Guidelines
- Keep changes small, focused, readable
- Avoid global state; no unnecessary dependencies
- **File limits**: ~300 lines/file, ~100 lines/function → split if exceeded
- Split large files: `controller_article.go`, `model_comment.go`, `functions_cache.go`

## Security
- **Never** print/return/log secrets, tokens, PII
- **Always** use parameterized queries: `db.Where("id = ?", id)` not string concat
- Validate all user input

## Development Workflow
1. **Read first**: Follow existing patterns, reuse utilities
2. **Plan**: Explain changes briefly, keep minimal
3. **Implement**: Add tests for behavior changes, preserve backward compatibility

---

## Project Structure
```
project/
├── cmd/app/main.go              # Entrypoint
├── apps/app_name/               # Modules
│   ├── app.go                   # Routes, registration, settings
│   ├── models.go                # GORM models
│   ├── controller.go            # HTTP handlers
│   ├── functions.go             # Helpers
│   └── serializer.go            # Request/response structs
├── library/                     # Shared utilities
├── docs/                        # Documentation
└── config.yml
```

## Configuration
```bash
./backend                        # Uses config.yml
./backend -c /path/to/config     # Custom config
./backend --migration-do         # Run migrations
```
```go
import "github.com/getevo/evo/v2/lib/settings"
settings.Get("DATABASE.HOST").String()
settings.Get("KEY").Int() / .Bool() / .Duration() / .SizeInBytes()
```

## Logging
```go
import "github.com/getevo/evo/v2/lib/log"
log.Info("msg") / log.Debug() / log.Warning() / log.Error() / log.Fatal()
log.Info("user %s logged in", username)
```

---

## App Template
```go
package myapp

import (
    "github.com/getevo/evo/v2"
    "github.com/getevo/evo/v2/lib/db"
)

type App struct{}
func (App) Name() string { return "myapp" }
func (App) Register() error { db.UseModel(MyModel{}); return nil }
func (App) Router() error {
    var ctrl Controller
    evo.Get("/api/v1/myapp/:id", ctrl.Get)
    evo.Post("/api/v1/myapp", ctrl.Create)
    return nil
}
func (App) WhenReady() error { go backgroundJob(); return nil }
```

| Method | Required | Description |
|--------|----------|-------------|
| `Name()` | Yes | App name |
| `Register()` | Yes | Register models |
| `Router()` | Yes | Define routes |
| `WhenReady()` | No | Post-init tasks |

---

## Model Definition

**Rules**: `TableNameID` as `int64` PK | `snake_case` columns/json | `fk:table` for FKs | `size:N` for strings | pointers for nullable | `restify.API` for REST

```go
type Article struct {
    ArticleID    int64      `gorm:"column:article_id;primaryKey;autoIncrement" json:"article_id"`
    Title        string     `gorm:"column:title;size:255" json:"title"`
    Status       string     `gorm:"column:status;type:enum('draft','published');default:draft" json:"status"`
    AuthorID     int64      `gorm:"column:author_id;fk:author" validation:"fk" json:"author_id"`
    Author       *Author    `gorm:"foreignKey:AuthorID;references:AuthorID" json:"author,omitempty"`
    PublishedAt  *time.Time `gorm:"column:published_at;default:NULL" json:"published_at"`
    types.CreatedAt
    types.UpdatedAt
    restify.API
}
func (Article) TableName() string { return "article" }
```

| GORM Tag | Example |
|----------|---------|
| Primary Key | `gorm:"column:id;primaryKey;autoIncrement"` |
| String | `gorm:"column:name;size:255"` |
| Enum | `gorm:"column:status;type:enum('a','b');default:a"` |
| FK Column | `gorm:"column:company_id;fk:company"` |
| FK Relation | `gorm:"foreignKey:CompanyID;references:CompanyID"` |
| Decimal | `gorm:"column:price;type:decimal(10,2)"` |

### Validation Tags
```go
type Article struct {
    Slug     string `validation:"slug,unique"`      // URL-safe + unique
    Email    string `validation:"email,required"`   // Email format + required
    AuthorID int64  `validation:"fk"`               // Foreign key exists
    Password string `validation:"password"`         // Password complexity
}
```

| Tag | Description |
|-----|-------------|
| `required` | Field must not be empty |
| `email` | Valid email format |
| `fk` | Foreign key must exist |
| `unique` | Value must be unique in table |
| `slug` | URL-safe string |
| `password` | Password complexity rules |

### Restify Hooks
```go
type Article struct {
    restify.API
}

// Lifecycle hooks - implement on model
func (a *Article) OnBeforeCreate(ctx *restify.Context) error { return nil }
func (a *Article) OnAfterCreate(ctx *restify.Context) error  { return nil }
func (a *Article) OnBeforeUpdate(ctx *restify.Context) error { return nil }
func (a *Article) OnAfterUpdate(ctx *restify.Context) error  { return nil }
func (a *Article) OnBeforeDelete(ctx *restify.Context) error { return nil }
func (a *Article) OnAfterDelete(ctx *restify.Context) error  { return nil }
func (a *Article) OnAfterGet(ctx *restify.Context) error     { return nil }

// Validation hooks
func (a *Article) ValidateCreate(ctx *restify.Context) error { return nil }
func (a *Article) ValidateUpdate(ctx *restify.Context) error { return nil }

// Permission hook
func (a *Article) RestPermission(p restify.Permissions, ctx *restify.Context) bool {
    return ctx.Request.User().HasPermission(roles.ArticleManage)
}
```

### Restify Disable Operations
```go
// Embed to disable specific REST operations
type Order struct {
    restify.API
    restify.DisableCreate  // Disable POST
    restify.DisableUpdate  // Disable PUT
    restify.DisableDelete  // Disable DELETE
    restify.DisableSet     // Disable bulk operations
}
```

---

## Authentication & Middleware

### Route Middleware
```go
evo.Use("/admin", ctrl.AdminMiddleware)
evo.Use("/api/v1/user", ctrl.UserAuthMiddleware)

func (c Controller) AdminMiddleware(r *evo.Request) error {
    if r.URL().Path == "/admin/login" { return r.Next() }  // Exclude auth routes
    if r.User().Anonymous() || !r.User().HasPermission(roles.DashboardLogin) {
        r.Status(evo.StatusUnauthorized)
        return fmt.Errorf("unauthorized")
    }
    return r.Next()
}
```

### Custom Auth Service (UserInterface)

Implement `evo.UserInterface` with `FromRequest` as the core auth method:

```go
type User struct {
    ID    uint64
    UUID  string
    Email string
    Roles []string
}

// Core auth method - called by request.User()
func (u *User) FromRequest(r *evo.Request) evo.UserInterface {
    token := strings.TrimPrefix(r.Header("Authorization"), "Bearer ")
    if token == "" { return nil }  // Anonymous

    claims, err := authService.ValidateToken(token)
    if err != nil { return nil }

    var user User
    db.Where("uuid = ?", claims.Subject).First(&user)
    user.Roles = claims.Roles
    return &user
}

// Required interface methods
func (u *User) Anonymous() bool { return u.UUID == "" }
func (u *User) HasPermission(p string) bool {
    for _, r := range u.Roles { if r == p { return true } }
    return false
}
func (u *User) ID() uint64           { return u.ID }
func (u *User) UUID() string         { return u.UUID }
func (u *User) GetEmail() string     { return u.Email }
func (u *User) GetFirstName() string { return "" }
func (u *User) GetLastName() string  { return "" }
func (u *User) GetFullName() string  { return "" }
func (u *User) Interface() any       { return u }
func (u *User) Attributes() evo.Attributes { return evo.Attributes{} }

// Register in app
func (App) Register() error {
    evo.SetUserInterface(&User{})
    return nil
}
```

### Multiple Auth Methods
```go
func (u *User) FromRequest(r *evo.Request) evo.UserInterface {
    header := r.Header("Authorization")

    // API Key auth
    if strings.HasPrefix(header, "APIKey ") {
        var user User
        if db.Where("api_key = ?", strings.TrimPrefix(header, "APIKey ")).First(&user).RowsAffected > 0 {
            return &user
        }
        return nil
    }

    // JWT Bearer auth
    if strings.HasPrefix(header, "Bearer ") {
        claims, err := validateJWT(strings.TrimPrefix(header, "Bearer "))
        if err != nil { return nil }
        return &User{UUID: claims.Sub, Roles: claims.Roles}
    }

    // Session cookie
    if sid := r.Cookie("session_id"); sid != "" {
        var user User
        if db.Where("session_id = ?", sid).First(&user).RowsAffected > 0 { return &user }
    }

    return nil
}
```

### API Key Authentication

```go
// API Key model
type APIKey struct {
    APIKeyID    int64  `gorm:"column:api_key_id;primaryKey;autoIncrement" json:"api_key_id"`
    Key         string `gorm:"column:key;size:64;unique;index" json:"-"`  // Never expose
    Name        string `gorm:"column:name;size:255" json:"name"`
    UserID      int64  `gorm:"column:user_id;fk:user" json:"user_id"`
    Permissions string `gorm:"column:permissions;size:1024" json:"permissions"`  // JSON array
    Active      bool   `gorm:"column:active;default:1" json:"active"`
    ExpiresAt   *time.Time `gorm:"column:expires_at" json:"expires_at"`
    types.CreatedAt
}
func (APIKey) TableName() string { return "api_key" }

// Generate secure API key
func GenerateAPIKey() string {
    b := make([]byte, 32)
    rand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}

// Validate in FromRequest
func (u *User) FromRequest(r *evo.Request) evo.UserInterface {
    header := r.Header("Authorization")

    // API Key: "APIKey sk_live_xxxxx"
    if strings.HasPrefix(header, "APIKey ") {
        key := strings.TrimPrefix(header, "APIKey ")
        var apiKey APIKey
        if db.Where("key = ? AND active = 1", key).First(&apiKey).RowsAffected == 0 {
            return nil
        }
        // Check expiration
        if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
            return nil
        }
        // Load associated user with API key permissions
        var user User
        db.First(&user, apiKey.UserID)
        json.Unmarshal([]byte(apiKey.Permissions), &user.Roles)
        return &user
    }

    // JWT Bearer fallback...
    return nil
}
```

**API Key Headers**: `Authorization: APIKey sk_live_xxxxx`

### Usage in Handlers
```go
func (c Controller) Handler(r *evo.Request) any {
    if r.User().Anonymous() { return errors.Unauthorized }
    if !r.User().HasPermission("admin") { return errors.Forbidden }
    user := r.User().Interface().(*User)  // Get typed user
    return outcome.OK(user)
}
```

---

## API Handlers
```go
// Handler signature
type Handler func(request *evo.Request) any

// Request helpers
request.Param("id").Int64()      // URL param
request.Query("page").Int()      // Query param
request.BodyParser(&input)       // Parse JSON body
request.User()                   // Auth user
request.Context()                // Context for DB ops
```

### Responses
```go
import "global/library/evo/lib/outcome"
import "global/library/evo/lib/errors"

// Success
return data                      // Auto-wrapped
return outcome.OK(data)          // 200
return outcome.Created(data)     // 201
return outcome.NoContent()       // 204

// Errors
return errors.BadRequest         // 400
return errors.Unauthorized       // 401
return errors.NotFound           // 404
return errors.Internal           // 500
return errors.New(400, "msg")    // Custom
```

### Complete Handler
```go
func (c Controller) Create(r *evo.Request) any {
    var input CreateInput
    if err := r.BodyParser(&input); err != nil { return errors.BadRequest }
    result, err := createItem(r.Context(), input)
    if err != nil { return errors.New(500, "failed") }
    return outcome.Created(result)
}
```

---

## Context & Transactions

**Context**: All I/O must accept `context.Context`. Use `request.Context()`. Never store in structs.
```go
func GetByID(ctx context.Context, id int64) (*Article, error) {
    var a Article
    return &a, db.WithContext(ctx).Where("id = ?", id).First(&a).Error
}
```

**Transactions**: Use `db.Transaction()`. Keep scope minimal. **Never** do network I/O inside transactions.
```go
err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
    if err := tx.Create(&article).Error; err != nil { return err }
    if err := tx.Create(&tag).Error; err != nil { return err }
    return nil  // Commit
})
// Network I/O AFTER transaction
notifyService(ctx, article)
```

---

## Background Tasks

| Type | Implementation | Example |
|------|----------------|---------|
| Multi-instance (all backends) | Goroutine in `WhenReady()` | Local cache cleanup |
| Single-instance (one backend) | API endpoint + external scheduler | DB maintenance |

```go
// Multi-instance: goroutine
func (App) WhenReady() error { go periodicCleanup(); return nil }

// Single-instance: API endpoint (document in docs/tasks.md)
evo.Get("/api/v1/app/tasks/cleanup", ctrl.TaskCleanup)
```

### Idempotency
Task endpoints **MUST** be idempotent. Use upserts or check state before action.
```go
// CORRECT: Upsert
db.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "external_id"}}, UpdateAll: true}).Create(&item)

// CORRECT: Check first
if db.Where("date = ?", today).First(&existing).Error == nil { return outcome.OK("exists") }
db.Create(&report)
```

---

## API Versioning
- Breaking changes → new version
- Document deprecations in `docs/api-deprecations.md`

| Requires New Version | No New Version |
|---------------------|----------------|
| Remove/rename field | Add optional field |
| Change field type | Add endpoint |
| Remove endpoint | Add query param |

---

## API Debug Mode
Header: `X-Debug: true` → Returns debug headers (execution time, cache info, query count). **Never** expose secrets/SQL/PII.

| Header | Meaning |
|--------|---------|
| `X-Execution-Time` | Duration (ms) |
| `X-Cache-Hit` | true/false |
| `X-DB-Queries` | Query count |

---

## Quick Reference

### Type Mappings
| Go | MariaDB |
|----|---------|
| `int64` | BIGINT |
| `string` | VARCHAR(size) |
| `bool` | TINYINT(1) |
| `time.Time` | DATETIME |
| `decimal.Decimal` | DECIMAL(p,s) |

### HTTP Status
| Code | Constant |
|------|----------|
| 200 | `outcome.OK()` |
| 201 | `outcome.Created()` |
| 400 | `errors.BadRequest` |
| 401 | `errors.Unauthorized` |
| 404 | `errors.NotFound` |
| 500 | `errors.Internal` |

### GORM Hooks
`BeforeCreate` `AfterCreate` `BeforeUpdate` `AfterUpdate` `BeforeSave` `AfterSave` `BeforeDelete` `AfterDelete` `AfterFind`
