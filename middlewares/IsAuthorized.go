package middlewares

import (
	"auth/utils"
	"github.com/gin-gonic/gin"
)

func IsAuthorized() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie := c.Request.Header.Get("Authorization")
		if cookie == "" {
			c.JSON(401, gin.H{"error": "unauthorized"})
			c.Abort()

			return
		}

		_, err := utils.ParseToken(cookie)

		if err != nil {
			c.JSON(401, gin.H{"error": "unauthorized"})
			c.Abort()

			return
		}

		c.Next()
	}
}
