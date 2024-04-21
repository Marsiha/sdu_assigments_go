package routes

import (
	"auth/controllers"
	"auth/middlewares"
	"github.com/gin-gonic/gin"
)

func AuthRoutes(r *gin.Engine) {

	h := r.Group("/")
	h2 := r.Group("/auth")
	h3 := r.Group("/")
	h.Use(middlewares.IsAuthorized())
	h2.POST("/login", controllers.Login)
	h2.POST("/signup", controllers.Signup)
	h.GET("/home", controllers.Home)
	h.GET("/users", controllers.GetUsers)
	h.GET("/premium", controllers.Premium)
	h3.GET("/fetch", controllers.Fetch)
	h3.GET("/fetchFile", controllers.FetchFromFile)
	h.GET("/logout", controllers.Logout)
}
