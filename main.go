package main

import (
	"fmt"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"golang.org/x/crypto/bcrypt"
)

var db *gorm.DB

type User struct {
	gorm.Model
	Username string
	Password string
}

func init() {
	var err error
	db, err = gorm.Open("mysql", "root:gabrielo2@tcp(localhost:3306)/login-system?charset=utf8&parseTime=True&loc=Local")
	if err != nil {
		fmt.Println(err)
	}

	db.AutoMigrate(&User{})
}

func main() {
	router := gin.Default()
	store := cookie.NewStore([]byte("secret"))
	router.Use(sessions.Sessions("mysession", store))

	router.LoadHTMLGlob("templates/*")

	router.GET("/login", loginForm)
	router.POST("/login", login)
	router.GET("/", dashboard)
	router.GET("/logout", logout)
	router.GET("/register", registerForm)
	router.GET("/dashboard", dashboard)
	router.POST("/register", register)

	router.Run(":8080")
}

func loginForm(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{})
}

func login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	var user User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"error": "Invalid username or password",
		})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"error": "Invalid username or password",
		})
		return
	}

	session := sessions.Default(c)
	session.Set("user_id", user.ID)
	session.Save()

	c.Redirect(http.StatusFound, "/dashboard")
}

func registerForm(c *gin.Context) {
	c.HTML(http.StatusOK, "register.html", gin.H{})
}

func register(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{
			"error": "Failed to create the user",
		})
		return
	}

	var user User
	if db.Where("username = ?", username).First(&user).RecordNotFound() {
		user := User{Username: username, Password: string(hashedPassword)}
		if err := db.Create(&user).Error; err != nil {
			c.HTML(http.StatusInternalServerError, "register.html", gin.H{
				"error": "Failed to create the user",
			})
			return
		}
		session := sessions.Default(c)
		session.Set("user_id", user.ID)
		session.Save()

		c.Redirect(http.StatusFound, "/login")
	} else {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"error": "The email is already taken",
		})
	}
}

func dashboard(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("user_id")
	if userID == nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	var user User
	if err := db.First(&user, userID).Error; err != nil {
		fmt.Println(err)
		c.HTML(http.StatusInternalServerError, "dashboard.html", gin.H{
			"error": "Failed to fetch user information",
		})
		return
	}

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"username": user.Username,
	})
}

func logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Delete("user_id")
	session.Save()
	c.Redirect(http.StatusFound, "/login")
}
