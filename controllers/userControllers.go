package controllers

import (
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"jwt-auth/initializers"
	models "jwt-auth/models"
)

func SignUp(context *gin.Context) {
	var body struct {
		Email    string
		Password string
	}

	//get the email / password from the request body

	newUSer := context.Bind(&body)

	if newUSer != nil {
		context.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to read the body",
		})
		return
	}

	//hash the password

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to hash password",
		})
		return
	}

	//create new user
	user := models.User{Email: body.Email, Password: string(hash)}

	result := initializers.DB.Create(&user)

	if result.Error != nil {
		context.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to create user",
		})
		return
	}

	//response
	context.JSON(http.StatusCreated, gin.H{
		"message": "user created successfully",
	})
}

func Login(context *gin.Context) {
	var body struct {
		Email    string
		Password string
	}

	//get the email / password from the request body

	newUSer := context.Bind(&body)

	if newUSer != nil {
		context.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to read the body",
		})
		return
	}

	//look for the email in db

	var user models.User

	initializers.DB.First(&user, "email = ?", body.Email)

	if user.ID == 0 {
		context.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid email",
		})
		return
	}

	//compare the given password with the hashed one in db

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{
			"error": "wrong password",
		})
		return
	}

	// create jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to create jwt token",
		})
		return
	}

	//save token as cookies
	context.SetSameSite(http.SameSiteLaxMode)
	context.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true) //always set secure true

	//response
	context.JSON(http.StatusOK, gin.H{
		"message": "logged in successfully",
	})

}

func Validate(context *gin.Context) {
	// Retrieve user from context
	user, exists := context.Get("user")
	if !exists {
		// User not found in context, respond with error
		context.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	// User found, respond with user data
	context.JSON(http.StatusOK, gin.H{
		"message": user,
	})
}
