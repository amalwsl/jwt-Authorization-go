package middleware

import (
	"fmt"
	"jwt-auth/initializers"
	models "jwt-auth/models"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func RequireAuth(context *gin.Context) {
	//get the cookies of request
	tokenString, err := context.Cookie("Authorization")

	fmt.Println("this is the token err => ", err)

	if err != nil || tokenString == "" {
		context.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// decode/validate it

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Secret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return ([]byte(os.Getenv("SECRET"))), nil
	})
	if err != nil {
		log.Fatal(err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		//check the expiration
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			context.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		//find the user with token sub
		var user models.User
		initializers.DB.First(&user, claims["sub"])

		if user.ID == 0 {
			context.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		//attach to request
		context.Set("user", user)

		//continue
		context.Next()
	} else {
		context.AbortWithStatus(http.StatusUnauthorized)
	}

}
