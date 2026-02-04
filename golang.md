# CLAUDE.md - Golang Project Guidelines

## Stack
`github.com/getevo/evo/v2` | `gorm.io/gorm` | `github.com/getevo/restify` | MariaDB | NATS + JetStream | REDIS (Universal connector to support both single instance and cluster)

## Claude Rules
- Follow existing patterns (even if suboptimal) | No refactor unless requested | Consistency over cleverness | Ask before new abstractions

## Guidelines
- Small, focused changes | No global state | ~300 lines/file, ~100 lines/function max
- **Security**: Never log secrets/PII | Parameterized queries only | Validate input

## Workflow
1. **Read**: Follow patterns, reuse utilities → 2. **Plan**: Minimal changes → 3. **Implement**: Test changes, backward compatible

---

## Structure
```
cmd/app/main.go                    # Entrypoint
apps/app_name/{app,models,controller,functions,serializer}.go
pkg/                           # Shared packages
docs/                              # Documentation
config.yml
```

## Config & Logging
```go
settings.Get("DATABASE.HOST").String()  // .Int() .Bool() .Duration() .SizeInBytes()
log.Info("msg") / log.Debug() / log.Warning() / log.Error() / log.Fatal()
```
```bash
./backend                        # config.yml default
./backend -c /path/to/config     # custom config
./backend --migration-do         # migrations
```

---

## App Template
```go
type App struct{}
func (App) Name() string    { return "myapp" }
func (App) Register() error { db.UseModel(Model{}); return nil }
func (App) Router() error   { evo.Get("/api/v1/x/:id", ctrl.Get); return nil }
func (App) WhenReady() error { go backgroundJob(); return nil }  // Optional
```

---

## Model
**Rules**: `TableNameID` int64 PK | `snake_case` | `fk:table` | `size:N` | pointer=nullable | `restify.API`

```go
type Article struct {
    ArticleID   int64      `gorm:"column:article_id;primaryKey;autoIncrement" json:"article_id"`
    Title       string     `gorm:"column:title;size:255" json:"title" validation:"required"`
    Status      string     `gorm:"column:status;type:enum('draft','published');default:draft" json:"status"`
    AuthorID    int64      `gorm:"column:author_id;fk:author" validation:"fk" json:"author_id"`
    Author      *Author    `gorm:"foreignKey:AuthorID;references:AuthorID" json:"author,omitempty"`
    PublishedAt *time.Time `gorm:"column:published_at" json:"published_at"`
    types.CreatedAt
    types.UpdatedAt
    restify.API
}
func (Article) TableName() string { return "article" }
```

| GORM | Example |
|------|---------|
| PK | `column:id;primaryKey;autoIncrement` |
| String | `column:name;size:255` |
| Enum | `column:status;type:enum('a','b');default:a` |
| FK | `column:x_id;fk:table` + `foreignKey:XID;references:XID` |
| Decimal | `column:price;type:decimal(10,2)` |

| Validation | `required` `email` `fk` `unique` `slug` `password` |

### Restify Hooks & Permissions
```go
// Lifecycle: OnBeforeCreate OnAfterCreate OnBeforeUpdate OnAfterUpdate OnBeforeDelete OnAfterDelete OnAfterGet
// Validation: ValidateCreate(ctx) ValidateUpdate(ctx)
func (a *Article) OnBeforeCreate(ctx *restify.Context) error { return nil }
func (a *Article) RestPermission(p restify.Permissions, ctx *restify.Context) bool {
    return ctx.Request.User().HasPermission(roles.Manage)
}

// Disable operations: embed restify.DisableCreate / DisableUpdate / DisableDelete / DisableSet
```

---

## Auth & Middleware
```go
evo.Use("/admin", ctrl.AdminMiddleware)

func (c Controller) AdminMiddleware(r *evo.Request) error {
    if r.URL().Path == "/admin/login" { return r.Next() }
    if r.User().Anonymous() || !r.User().HasPermission(roles.Admin) {
        r.Status(401); return fmt.Errorf("unauthorized")
    }
    return r.Next()
}
```

### UserInterface Implementation
```go
type User struct { ID uint64; UUID, Email string; Roles []string }

func (u *User) FromRequest(r *evo.Request) evo.UserInterface {
    h := r.Header("Authorization")
    // APIKey auth
    if strings.HasPrefix(h, "APIKey ") {
        var ak APIKey
        if db.Where("key=? AND active=1", strings.TrimPrefix(h,"APIKey ")).First(&ak).RowsAffected == 0 { return nil }
        if ak.ExpiresAt != nil && ak.ExpiresAt.Before(time.Now()) { return nil }
        var user User; db.First(&user, ak.UserID)
        json.Unmarshal([]byte(ak.Permissions), &user.Roles)
        return &user
    }
    // JWT Bearer auth
    if strings.HasPrefix(h, "Bearer ") {
        claims, err := validateJWT(strings.TrimPrefix(h, "Bearer "))
        if err != nil { return nil }
        var user User; db.Where("uuid=?", claims.Sub).First(&user)
        user.Roles = claims.Roles; return &user
    }
    return nil
}

func (u *User) Anonymous() bool { return u.UUID == "" }
func (u *User) HasPermission(p string) bool { for _,r := range u.Roles { if r==p { return true }}; return false }
func (u *User) ID() uint64 { return u.ID }
func (u *User) UUID() string { return u.UUID }
func (u *User) GetEmail() string { return u.Email }
func (u *User) GetFirstName() string { return "" }
func (u *User) GetLastName() string { return "" }
func (u *User) GetFullName() string { return "" }
func (u *User) Interface() any { return u }
func (u *User) Attributes() evo.Attributes { return evo.Attributes{} }

// Register: evo.SetUserInterface(&User{})
```

### APIKey Model
```go
type APIKey struct {
    APIKeyID    int64      `gorm:"column:api_key_id;primaryKey;autoIncrement" json:"api_key_id"`
    Key         string     `gorm:"column:key;size:64;unique;index" json:"-"`
    UserID      int64      `gorm:"column:user_id;fk:user" json:"user_id"`
    Permissions string     `gorm:"column:permissions;size:1024" json:"permissions"`
    Active      bool       `gorm:"column:active;default:1" json:"active"`
    ExpiresAt   *time.Time `gorm:"column:expires_at" json:"expires_at"`
    types.CreatedAt
}
func GenerateAPIKey() string { b:=make([]byte,32); rand.Read(b); return base64.URLEncoding.EncodeToString(b) }
```
Header: `Authorization: APIKey sk_live_xxxxx`

---

## Handlers
```go
type Handler func(r *evo.Request) any

r.Param("id").Int64()    // URL param
r.Query("page").Int()    // Query param
r.BodyParser(&input)     // JSON body
r.User()                 // Auth user
r.Context()              // For DB ops

// Success: return data | outcome.OK(data) | outcome.Created(data) | outcome.NoContent()
// Errors: errors.BadRequest | errors.Unauthorized | errors.NotFound | errors.Internal | errors.New(400,"msg")

func (c Ctrl) Create(r *evo.Request) any {
    var in Input; if r.BodyParser(&in) != nil { return errors.BadRequest }
    res, err := create(r.Context(), in); if err != nil { return errors.Internal }
    return outcome.Created(res)
}
```
 ## outcome                                                                                                                                                                                                                                                                                                                             `github.com/getevo/v2/lib/outcome` — HTTP response builder for evo handlers.     
Constructors (all accept optional any, auto-marshaled):
`OK`, `Created`, `NoContent`, `BadRequest`, `UnAuthorized`, `NotFound`, `InternalServerError`, `Json`, `Text`, `Html`, `Redirect`

Chainable methods: `.Status(code)`, `.Header(k,v)`, `.Cookie(k,v,ttl)`, `.Error(msg,code)`, `.Filename(n)`, `.SetCacheControl(dur)`
```go
  import "github.com/getevo/v2/lib/outcome"
  func GetUser(r *evo.Request) any {
      user, err := db.Find(r.Param("id"))
      if err != nil {
          return outcome.NotFound("not found")
      }
      return outcome.OK(user).Header("x-custom-header","some-text")
  }

  // custom output with manual serializaiton
  func GetUser2(r *evo.Request) any {
      user, err := db.Find(r.Param("id"))
      if err != nil {
          return outcome.NotFound("not found")
      }
      data, _ := json.Marshal(a)
      return outcome.Response{
          ContentType: "application/json",
          StatusCode:  200,
          Data:        data,
     }.Header("x-custom-header","some-text")
  }
```
---

## Context & Transactions
```go
// Context: All I/O accepts context.Context. Use r.Context(). Never store in structs.
func GetByID(ctx context.Context, id int64) (*Article, error) {
    var a Article; return &a, db.WithContext(ctx).Where("id=?", id).First(&a).Error
}

// Transactions: Minimal scope. NO network I/O inside.
db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
    if tx.Create(&a).Error != nil { return err }
    return nil
})
notifyService(ctx, a)  // Network AFTER transaction
```

---

## Background Tasks
| Multi-instance | Goroutine in `WhenReady()` | Local cache cleanup |
| Single-instance | API endpoint `/api/v1/app/tasks/x` + scheduler | DB maintenance |

**Idempotency**: Tasks MUST be idempotent. Use upserts or check-before-action.
```go
db.Clauses(clause.OnConflict{Columns:[]clause.Column{{Name:"id"}},UpdateAll:true}).Create(&x)
```
Document in `docs/tasks.md`

---

## API Versioning & Debug
- Breaking changes → new version | Document deprecations in `docs/api-deprecations.md`
- `X-Debug: true` header → Returns `X-Execution-Time`, `X-Cache-Hit`, `X-DB-Queries` (never secrets)

---

## Reference

| Go Type | MariaDB | Status | Constant |
|---------|---------|--------|----------|
| `int64` | BIGINT | 200 | `outcome.OK()` |
| `string` | VARCHAR | 201 | `outcome.Created()` |
| `bool` | TINYINT(1) | 400 | `errors.BadRequest` |
| `time.Time` | DATETIME | 401 | `errors.Unauthorized` |
| `decimal.Decimal` | DECIMAL | 404 | `errors.NotFound` |
| `*T` | NULL | 500 | `errors.Internal` |

**GORM Hooks**: `BeforeCreate` `AfterCreate` `BeforeUpdate` `AfterUpdate` `BeforeSave` `AfterSave` `BeforeDelete` `AfterDelete` `AfterFind`


## Command-Line Arguments

Use `github.com/getevo/evo/v2/lib/args` for CLI args. [Full docs](https://github.com/getevo/evo/blob/master/docs/args.md)

```go
import "github.com/getevo/evo/v2/lib/args"

// ./app --config /path/to/config.yml --debug --port 8080
args.Exists("--debug")           // true if flag present
args.Get("--config").String()    // "/path/to/config.yml"
args.Get("--port").Int()         // 8080
```

## HTTP API Calls (API Calls)

**Always use `github.com/getevo/evo/v2/lib/curl` for HTTP requests.** [Full docs](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/curl.md)

```go
import "github.com/getevo/evo/v2/lib/curl"

// Requests - options can be combined in any order
resp, err := curl.Get(url)
resp, err := curl.Get(url, curl.BasicAuth{Username: "u", Password: "p"}, 30*time.Second)
resp, err := curl.Post(url, curl.BodyJSON(payload), curl.Header{"X-Key": []string{"val"}})
resp, err := curl.Post(url, curl.Param{"key": "value"})  // form data
resp, err := curl.Put(url, curl.BodyRaw("raw content"))  // string, []byte, or io.Reader
// Also: Patch, Delete, Head, Options, Do("METHOD", url, opts...)

// Response handling
if resp.Status() >= 400 { return err }
resp.Dot("data.items.0.name").String()  // JSON dot notation
resp.Dot("meta.total").Int()            // .Float(), .Bool(), .Array(), .Map()
resp.ToJSON(&result)                    // unmarshal to struct
resp.String()                           // raw body as string
resp.Bytes()                            // raw body as []byte

// Debug: curl.Debug = true | resp.Dump() | resp.Cost() (ms)
```
## Dot Notation

Use `github.com/getevo/evo/v2/lib/dot` for nested data access. [Full docs](https://github.com/getevo/evo/blob/master/docs/dot.md)

```go
import "github.com/getevo/evo/v2/lib/dot"

// Get nested values from maps, structs, slices
val, err := dot.Get(data, "user.address.city")
val, err := dot.Get(data, "users[0].name")       // array index
val, err := dot.Get(data, "items[2].tags[0]")    // nested arrays

// Set nested values (use pointer for structs)
err := dot.Set(&data, "user.address.city", "Rome")
err := dot.Set(&data, "users[0].active", true)

// Type conversion (returns any, cast as needed)
city := val.(string)
```

## File Operations

Use `github.com/getevo/evo/v2/lib/gpath` for file/path operations. [Full docs](https://github.com/getevo/evo/blob/master/lib/gpath/README.md)

```go
import "github.com/getevo/evo/v2/lib/gpath"

// Path utilities
gpath.WorkingDir()                          // current working directory
gpath.Parent("/path/to/file.txt")           // "/path/to"
gpath.IsDirExist("/path"), gpath.IsFileExist("/path/file.txt")
gpath.IsDirEmpty("/path")

// File operations
gpath.Write("/path/file.txt", []byte("content"))
gpath.Append("/path/file.txt", []byte("more"))
content, _ := gpath.Read("/path/file.txt")  // returns []byte
gpath.ReadJSON("/path/file.json", &obj)     // unmarshal JSON file
gpath.WriteJSON("/path/file.json", obj)     // marshal to JSON file

// Directory operations
gpath.MakePath("/path/to/nested/dir")       // create nested dirs
gpath.CopyDir("/src", "/dst")
gpath.CopyFile("/src/file", "/dst/file")
```

## Validation

Use `validation` struct tags. [Full docs](https://github.com/getevo/evo/blob/master/docs/validation.md)

```go
import "github.com/getevo/evo/v2/lib/validation"

type User struct {
    Email  string `validation:"required,email"`
    Age    int    `validation:">=18,<120"`
    Phone  string `validation:"phone"`
    URL    string `validation:"url"`
}

err := validation.Struct(user)              // validate all fields
err := validation.StructNonZeroFields(user) // validate non-empty only (for updates)
err := validation.Value(email, "required,email") // validate single value

// Common tags: required, email, url, phone, uuid, ip, ip4, ip6, cidr, mac,
// alpha, alphanumeric, json, creditcard, len>=N, >=N, <N, unique, fk, enum
```
