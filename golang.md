# CLAUDE.md - Golang Project Guidelines

## Stack
`github.com/getevo/evo/v2` | `gorm.io/gorm` | `github.com/getevo/restify` | MariaDB | NATS + JetStream | REDIS

## Core Imports
| Alias | Import |
|-------|--------|
| `evo` | `github.com/getevo/evo/v2` |
| `db` | `github.com/getevo/evo/v2/lib/db` |
| `types` | `github.com/getevo/evo/v2/lib/db/types` |
| `errors` | `github.com/getevo/evo/v2/lib/errors` |
| `log` | `github.com/getevo/evo/v2/lib/log` |
| `settings` | `github.com/getevo/evo/v2/lib/settings` |
| `outcome` | `github.com/getevo/evo/v2/lib/outcome` |
| `restify` | `github.com/getevo/restify` |
| `pubsub` | `github.com/getevo/evo/v2/lib/pubsub` |
| `application` | `github.com/getevo/evo/v2/lib/application` |

## Claude Rules
- Follow existing patterns | No refactor unless requested | Consistency over cleverness | Ask before new abstractions
- **Living Docs**: After each instruction, update `CLAUDE.md`, `docs/`, plan files to reflect decisions/patterns.
- **Changelog**: After git push of feature/fix → append to `./changelog/changelog-{mon}-{year}.md`: `- YYYY-MM-DD | feat|fix|refactor|chore | description`

## Guidelines
- Small focused changes | No global state | ~300 lines/file ~100 lines/function | Parameterized queries | Validate input | Never log secrets/PII

## Workflow
Read patterns → Plan minimal changes → Implement backward-compatible

---

## Structure
```
main.go
apps/app_name/{app,models,controller,functions,serializer}.go
pkg/roles/roles.go           # permission constants (roles.Admin, roles.Manage, …)
pkg/utils/                   # shared helpers
docs/                        # documentation
changelog/changelog-{mon}-{year}.md
config.yml → https://raw.githubusercontent.com/getevo/claude/refs/heads/main/config.example.yml
```

## Config & Logging
[Settings](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/configuration.md) | [Log](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/log.md) | [FileLogger](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/file_logger.md)
```go
settings.Get("KEY").String() // .Int() .Bool() .Duration() .Default(val)
settings.Track("APP.*", func() { /* fires immediately + on every config change */ })
log.Info/Debug/Warning/Error/Fatal("msg")
log.WithField("k", v).Info("msg") | log.WithFields(map[string]any{"k": v}).Error("msg")
```
```bash
./backend [-c config.yml] [--migration-do]
```

---

## App Template
> Lifecycle: `Register()` all → HTTP starts → `WhenReady()` all → `OnShutdown` on SIGTERM

```go
type App struct{}
func (App) Name() string    { return "myapp" }   // required
func (App) Register() error {                     // optional
    db.UseModel(M1{}, M2{}, M3{})                // variadic
    pubsub.SetDefaultDriver(natspkg.Driver)       // if using NATS as default pub/sub
    settings.Track("APP.*", func() { initClient() })
    return nil
}
func (App) Router() error {                       // optional
    v1 := evo.Group("/api/v1")                   // .Use() for group-scoped middleware
    v1.Get("/x/:id", ctrl.Get)
    evo.Use(globalMW)                            // global; evo.Use("/path", mw) for path-scoped
    evo.Static("/assets", "./public")            // SPA: evo.Static("/", "./public/index.html")
    return nil
}
func (App) WhenReady() error {                    // optional
    go backgroundJob()
    evo.OnShutdown(func() { cleanup() })
    evo.OnHealthCheck(func() error { return redis.Driver.Ping() }) // liveness
    evo.OnReadyCheck(func() error { return db.Ping() })            // readiness / K8s probe
    return nil
}
```

**main.go** — Setup/Run return `error` since Feb 2026 ([CRITICAL_FIXES](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/CRITICAL_FIXES.md)):
```go
func main() {
    if err := evo.Setup(mysql.Driver{}); err != nil { log.Fatal(err) }
    application.GetInstance().Register(MyApp{}, OtherApp{})
    if err := evo.Run(); err != nil { log.Fatal(err) }
}
// Raw Fiber: evo.GetFiber() → *fiber.App (use sparingly for middleware/websockets not wrapped by evo)
```

---

## Model
[Database](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/database.md) | [Migration](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/migration.md)
Rules: `TableNameID int64 PK` | `snake_case` | `fk:table` | `size:N` | pointer=nullable | embed `restify.API`

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
    types.SoftDelete  // optional; embed when soft delete needed
    restify.API
}
func (Article) TableName() string { return "article" }
// Shared fields → extract Base struct (types.CreatedAt/UpdatedAt/SoftDelete + restify.API) and embed
```

GORM tags: `primaryKey;autoIncrement` | `size:255` | `type:enum('a','b');default:a` | `fk:table`+`foreignKey:XID;references:XID` | `type:decimal(10,2)`
Validation tags: `required` `email` `fk` `unique` `slug` `password` `url` `phone` `uuid`

### DB Types — always use instead of raw Go types (`github.com/getevo/evo/v2/lib/db/types`)
| Type | Column | Notes |
|------|--------|-------|
| `types.CreatedAt` / `types.UpdatedAt` | DATETIME | auto-set; embed in every model |
| `types.SoftDelete` | deleted+deleted_at | `.Delete()` `.Restore()` `.IsDeleted()`; GORM auto-filters `deleted=0` |
| `types.Archive` | archive TINYINT | `.SetArchive(bool)` |
| `types.UUID` | CHAR(36) | `NewUUID()` `NewUUIDv4()` `NewUUIDv1()` |
| `types.Time` | TIME | `NewTime(h,m,s,ns)` |
| `types.StringArray` / `IntArray` / `Int64Array` | JSON | typed JSON arrays |
| `types.JSONType[T]` / `JSONSlice[T]` / `JSONMap` | JSON | struct/slice/map as JSON column |
| `types.URL` | VARCHAR | URL with scan/value |

### Restify — Auto REST (default prefix `/admin/restify`, override: `restify.SetPrefix("/api/v1")`)
Endpoints: `PUT /model` create | `PUT /model/batch` | `GET /model/all` | `GET /model/paginate` | `GET /model/:id` | `PATCH /model/:id` | `PATCH /model/batch` | `POST /model/set` upsert | `DELETE /model/:id` | `DELETE /model/batch` | `GET /model/aggregate`

Query: `field[eq|neq|gt|lt|gte|lte|in|between|contains|search|isnull|notnull]=val` | `order=f.asc` | `fields=f1,f2` | `associations=Orders.Product` or `*` | `offset/limit` | `page/size` | `group_by=f` | `?debug=restify`

**Hooks** — all receive `ctx.DB *gorm.DB` (current tx) and `ctx.Request.User()`:
```go
func (a *Article) OnBeforeCreate(ctx *restify.Context) error {
    a.UserID = int64(ctx.Request.User().GetID()); return nil
}
// Hooks: OnBeforeCreate OnAfterCreate OnBeforeUpdate OnAfterUpdate OnBeforeSave OnAfterSave
//        OnBeforeDelete OnAfterDelete OnAfterGet
// Validate: ctx.AddValidationErrors(err); if len(ctx.ValidationErrors)>0 { return err }
func (a *Article) ValidateCreate(ctx *restify.Context) error { return nil } // also ValidateUpdate
// Global: restify.OnBeforeSave(func(obj any, ctx *restify.Context) error { return nil })
```

**Permissions & row-level security:**
```go
func (a *Article) RestPermission(p restify.Permissions, ctx *restify.Context) bool {
    user := ctx.Request.User()
    if user.Anonymous() { ctx.Error(fmt.Errorf("unauthorized"), 401); return false }
    ctx.SetCondition("user_id", "=", user.GetID())  // row-level filter on all queries
    ctx.Override(Article{UserID: user.GetID()})      // force field on writes
    return !p.Has("DELETE") || user.HasPermission(roles.Admin)
}
// p.Has: VIEW CREATE UPDATE DELETE BATCH SET AGGREGATE
// Global default: restify.SetDefaultPermissionHandler(func(p Permissions, ctx *Context) bool { ... })
// Disable: embed restify.DisableCreate/Update/Delete/Set/List/Aggregate
// Soft delete: types.SoftDelete — restify calls .Delete() instead of hard DELETE
```

---

## Auth & Middleware
`pkg/roles/roles.go`: `const ( Admin = "admin"; Manage = "manage"; Editor = "editor" )`
```go
evo.Use(globalMW) | evo.Use("/admin", authMW)   // global or path-prefix scoped

func (c Ctrl) AuthMW(r *evo.Request) error {
    if r.User().Anonymous() { r.Status(401); return fmt.Errorf("unauthorized") }
    return r.Next()
}
```

**UserInterface** — implement and register with `evo.SetUserInterface(&User{})`:
```go
type User struct { UserID uint64; UUID, Email string; Roles []string }

func (u *User) FromRequest(r *evo.Request) evo.UserInterface {
    h := r.Header("Authorization")
    if strings.HasPrefix(h, "APIKey ") {
        // lookup APIKey{Key, UserID, Permissions, Active, ExpiresAt} from DB; load roles from Permissions JSON
    }
    if strings.HasPrefix(h, "Bearer ") {
        // validate JWT; load user by claims.Sub; set Roles from claims
    }
    return nil  // anonymous
}
func (u *User) Anonymous() bool         { return u.UUID == "" }
func (u *User) HasPermission(p string) bool { for _, r := range u.Roles { if r == p { return true } }; return false }
// Also required: GetID() GetEmail() GetFirstName() GetLastName() GetFullName() UUID() Interface() Attributes()
```

APIKey model fields: `Key string` (size:64,unique,index), `UserID int64 fk:user`, `Permissions string` (JSON roles array), `Active bool default:1`, `ExpiresAt *time.Time`, `types.CreatedAt`
Header: `Authorization: APIKey sk_live_xxx` | Generate: `base64.URLEncoding.EncodeToString(32 random bytes)`

---

## Handlers
[Webserver docs](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/webserver.md)
```go
r.Param("id").Int64() | r.Query("page").Int() | r.BodyParser(&input) | r.User() | r.Context()
r.IP() | r.Header("X-ID") | r.Method() | r.URL().Path
r.Cookie("s") | r.SetCookie("s", token, 24*time.Hour)

// errors: BadRequest(400) Unauthorized(401) Forbidden(403) NotFound(404) Conflict(409) Internal(500) + all 4xx
// Custom: errors.New("msg", 400) | errors.New(err, 422) | errors.New("msg").Code(503)

func (c Ctrl) Create(r *evo.Request) any {
    var in Input
    if err := r.BodyParser(&in); err != nil { return errors.BadRequest }
    if err := validation.Struct(in); err != nil { return errors.New(err.Error(), 422) }
    res, err := create(r.Context(), in)
    if err != nil { return errors.Internal }
    return outcome.Created(res)
}
```

**outcome** ([docs](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/outcome.md)) — `github.com/getevo/evo/v2/lib/outcome`:
```go
outcome.OK(data).Header("k","v").SetCacheControl(5*time.Minute)
outcome.Redirect("/login") | outcome.Redirect("/new", 301)
outcome.File("/f.pdf").Filename("report.pdf") | outcome.Json(bytes) | outcome.Text("str")
outcome.Response{ContentType:"application/json", StatusCode:200, Data:data}
```

---

## Context & Transactions
```go
// Always pass context.Context to all I/O; use r.Context() in handlers
func GetByID(ctx context.Context, id int64) (*Article, error) {
    var a Article; return &a, db.WithContext(ctx).Where("id=?", id).First(&a).Error
}
db.WithContext(ctx).Transaction(func(tx *gorm.DB) error { return tx.Create(&a).Error })
notifyService(ctx, a)   // network AFTER transaction; never inside
db.GetInstance()        // *gorm.DB — raw access when needed by external packages
```

---

## Background Tasks
- **Multi-instance**: goroutine in `WhenReady()`
- **Single-instance**: API endpoint `/api/v1/app/tasks/x` + scheduler; document in `docs/tasks.md`
- **Idempotency required**: `db.Clauses(clause.OnConflict{Columns:[]clause.Column{{Name:"id"}},UpdateAll:true}).Create(&x)`

---

## Libraries

**args** `lib/args` — [docs](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/args.md): `args.Exists("--debug")` | `args.Get("--port").Int()`

**curl** `lib/curl` — [docs](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/curl.md):
```go
resp, err := curl.Get(url, 30*time.Second) | curl.Post(url, curl.BodyJSON(p)) | curl.Post(url, curl.Param{"k":"v"})
resp.Dot("data.name").String() | resp.ToJSON(&r) | resp.Status()
if resp.Status() >= 400 { return errors.New(resp.String(), resp.Status()) }
```

**validation** `lib/validation` — [docs](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/validation.md):
`validation.Struct(v)` | `validation.StructNonZeroFields(v)` (for PATCH) | tags: `required email fk unique url phone uuid >=N`

**dot** `lib/dot` — [docs](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/dot.md): `dot.Get(data, "user.items[0].name")` | `dot.Set(&data, "path", val)`

**gpath** `lib/gpath`: `gpath.WorkingDir()` | `gpath.Write/Read/MakePath/IsFileExist/ReadJSON/WriteJSON`

**generic** `lib/generic`: `generic.Parse(v).String()/.Int64()/.Bool()/.Time()/.IsNil()` — safe `any`→type conversion

**ptr** `lib/ptr`: `ptr.String("x")` | `ptr.Int64(42)` | `ptr.Bool(true)` | `ptr.Time(t)` — literals to pointers for nullable fields

**async** `lib/async`:
```go
async.ForEach(items, func(i *T) { ... })                      // parallel, GOMAXPROCS goroutines
results, err := async.MapErr(items, func(i *T) (R, error) {}) // parallel map with errors
p := async.NewPool().WithErrors().WithMaxGoroutines(10); p.Exec(fn); p.Wait()
async.All(ctx, fn1, fn2)      // concurrent, collect all — Executable=func(ctx)(any,error)
async.Retry(ctx, 3, fn)       // retry on error
async.Waterfall(ctx, s1, s2)  // sequential pipeline — each fn receives previous result
```

**try** `lib/try`: `try.This(fn).Catch(func(r *panics.Recovered){}).Finally(cleanup)`

**tpl** `lib/tpl`: `tpl.Render("Hello $name at $obj.field", map[string]any{"name":"World"})`

**storage** `lib/storage`: `storage.NewStorageInstance("local", "fs:///path")` | `storage.GetStorage("local").Write(...)`

**reflections** `lib/reflections` — [docs](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/reflections.md): get/set/inspect struct fields by name or tag at runtime

**pagination** `github.com/getevo/pagination` — returns `HTTPSerializer`, return `p` directly from handler:
```go
p, err := pagination.New(db.Model(&Order{}), request, &items, pagination.Options{MaxSize:50, SortFields:[]string{"created_at"}, BaseURL:"..."})
// also: NewWithContext(ctx,...) | NewFromParams(db, page, size, &items, opts)
// response: records pages current_page has_next has_prev | sort: ?sort=f1,f2&order=asc,desc
```

**NATS** `lib/connectors/nats` — [docs](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/nats.md):
```go
// Setup: pubsub.SetDefaultDriver(natspkg.Driver) in Register(); config: NATS.SERVER NATS.DEFAULT_BUCKET
pubsub.Subscribe("topic", func(topic string, msg []byte, driver pubsub.Interface) { driver.Unmarshal(msg, &e) })
pubsub.Publish("topic", payload)
natspkg.Driver.Publish("topic", p, natspkg.WithJetStream)              // at-least-once with server ack
natspkg.Driver.Subscribe("t", handler, natspkg.Queue("workers"))       // queue group
natspkg.Driver.Set/Get/Delete(key, ..., natspkg.Bucket("name"))        // JetStream KV (bucket-level TTL only)
// Raw: natspkg.Connection (*nats.Conn) | natspkg.JS (JetStreamContext)
```

**Redis** `lib/connectors/redis` — [docs](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/redis.md):
```go
// Setup: evo.Setup(redis.Driver); config: CACHE.REDIS_ADDRESS (comma-sep=cluster) CACHE.REDIS_PREFIX
redis.Driver.Set(key, val, ttl) | redis.Driver.Get(key, &dest) | redis.Driver.Exists(key)
redis.Driver.SetNX(key, val, ttl)          // atomic set-if-not-exists — distributed locking
redis.Driver.Increment/Decrement(key, n) | redis.Driver.Keys(pattern) | redis.Driver.Delete(key)
redis.Driver.Publish/Subscribe("topic", handler)  // same handler signature as NATS
// Raw: redisconn.Client (redis.UniversalClient) — Pipeline, Hash, SortedSet, etc.
```

---

## API Versioning & Debug
- Breaking changes → new version; document in `docs/api-deprecations.md`
- `X-Debug: true` header → `X-Execution-Time` `X-Cache-Hit` `X-DB-Queries` (never secrets)

---

## Docs Reference
> Fetch and read the linked doc before working in that area.

| Doc | When / what's inside |
|-----|----------------------|
| [ai_guideline](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/ai_guideline.md) | **Start here when unsure which package to use** — full package map, import paths, all libs |
| [configuration](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/configuration.md) | All YAML keys, env override, priority order (CLI>env>YAML>DB), `settings.Bind` |
| [database](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/database.md) | Connection pool (`MaxOpenConns` etc.), debug levels 1–4, driver interface |
| [webserver](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/webserver.md) | Full routing API, wildcards, `SetRawCookie`, middleware chain |
| [health-checks](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/health-checks.md) | `OnHealthCheck/OnReadyCheck`, `db.Ping/WaitForDB`, K8s probe integration |
| [log](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/log.md) | All levels, `SetLevel`, `AddWriter(fn)`, `log.Entry` struct |
| [file_logger](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/file_logger.md) | File log with midnight rotation; `Config{Path,FileName,Expiration}`; `%y %m %d` wildcards |
| [migration](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/migration.md) | Versioned migrations with rollback, `Migration(version)` hook, nullable via pointers |
| [mysql](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/mysql.md) | `mysql.Driver{}` config, MariaDB auto-detect, TiDB, recommended Params |
| [pgsql](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/pgsql.md) | `pgsql.Driver{}`, Schema, SSLMode, multi-tenant setup |
| [outcome](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/outcome.md) | All response constructors and chainable methods |
| [reflections](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/reflections.md) | Runtime struct field access by name or tag |
| [tpl](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/tpl.md) | `$var` `$obj.field` `$arr[0]` template syntax, multi-source params |
| [nats](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/nats.md) | Full NATS config, Queue groups, CreateBucket, raw Connection/JS |
| [redis](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/redis.md) | Full Redis config, GetWithExpiration, UnsubscribeAll, cluster caveats |
| [CRITICAL_FIXES](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/CRITICAL_FIXES.md) | Setup/Run return error since Feb 2026 — check when writing main.go |
| [MIGRATION_GUIDE](https://raw.githubusercontent.com/getevo/evo/refs/heads/master/docs/MIGRATION_GUIDE.md) | Steps to update from old void Setup/Run API |
