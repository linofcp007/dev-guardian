package main

import "github.com/gin-gonic/gin"

func ginRouter() *gin.Engine {
	r := gin.Default()

	// Not a route: `Use` is not an HTTP verb, so the verb guard excludes it.
	r.Use(gin.Recovery())

	r.GET("/gin/ping", pong)
	r.POST("/gin/items", createItem)
	r.DELETE("/gin/items/:id", deleteItem)

	return r
}

func pong(c *gin.Context)       { c.String(200, "pong") }
func createItem(c *gin.Context) { c.Status(201) }
func deleteItem(c *gin.Context) { c.Status(204) }
