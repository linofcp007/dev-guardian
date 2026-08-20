package main

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/labstack/echo/v4"
	myjson "encoding/json"
)

func main() {
	mux := http.NewServeMux()
	// G01 control
	mux.HandleFunc("/go/health", handler)
	// G02 Go 1.22 method-in-pattern
	mux.HandleFunc("GET /go/items/{id}", handler)
	// G03 mux.Handle (not HandleFunc) — very common with http.Handler values
	mux.Handle("/go/static/", http.StripPrefix("/go/static/", http.FileServer(http.Dir("."))))
	// G04 package-level
	http.HandleFunc("/go/legacy", handler)

	// G05 gin (control)
	r := gin.Default()
	r.GET("/gin/ping", func(c *gin.Context) {})
	// G06 gin group
	v1 := r.Group("/api/v1")
	v1.POST("/items", func(c *gin.Context) {})

	// G07 chi — Get/Post are TitleCase, not SCREAMING
	cr := chi.NewRouter()
	cr.Get("/chi/items", handler)
	cr.Post("/chi/items", handler)
	cr.Route("/chi/sub", func(r chi.Router) { r.Get("/x", handler) })

	// G08 echo — SCREAMING like gin
	e := echo.New()
	e.GET("/echo/items", func(c echo.Context) error { return nil })

	_ = myjson.Marshal
	_ = os.Getenv("GO_ENV")
}

func handler(w http.ResponseWriter, r *http.Request) {}
