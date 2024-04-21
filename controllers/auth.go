package controllers

import (
	"auth/models"
	"auth/utils"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

// The string "my_secret_key" is just an example and should be replaced with a secret key of sufficient length and complexity in a real-world scenario.
var jwtKey = []byte("mysecret")

func Login(c *gin.Context) {

	var user models.User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var existingUser models.User

	models.DB.Where("email = ?", user.Email).First(&existingUser)

	if existingUser.ID == 0 {
		c.JSON(400, gin.H{"error": "user does not exist"})
		return
	}

	errHash := utils.CompareHashPassword(user.Password, existingUser.Password)

	if !errHash {
		c.JSON(400, gin.H{"error": "invalid password"})
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)

	claims := &models.Claims{
		Role: existingUser.Role,
		StandardClaims: jwt.StandardClaims{
			Subject:   existingUser.Email,
			ExpiresAt: time.Now().Add(time.Duration(time.Minute) * 60).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		logrus.Error("[USER-LOGIN] Error logging user: ", err)
		c.JSON(500, gin.H{"error": "could not generate token"})
		return
	}
	logrus.Info("[USER-LOGIN] User logged in", err)
	c.SetCookie("token", tokenString, int(expirationTime.Unix()), "/", "localhost", false, true)
	c.JSON(200, tokenString)
}

func Signup(c *gin.Context) {
	var user models.User

	if err := c.ShouldBindJSON(&user); err != nil {
		logrus.Error("[USER_REGISTER] Error creating user: ", err)
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var existingUser models.User

	models.DB.Where("email = ?", user.Email).First(&existingUser)

	if existingUser.ID != 0 {
		c.JSON(400, gin.H{"error": "user already exists"})
		return
	}

	var errHash error
	user.Password, errHash = utils.GenerateHashPassword(user.Password)

	if errHash != nil {
		c.JSON(500, gin.H{"error": "could not generate password hash"})
		return
	}

	models.DB.Create(&user)
	logrus.Info("[USER-REGISTER] User created with id: ", user.ID)
	c.JSON(200, gin.H{"success": "user created"})
}

func Home(c *gin.Context) {
	c.JSON(200, gin.H{"success": "home page"})
}

func GetUsers(c *gin.Context) {
	users := []models.User{}
	models.DB.Find(&users)

	if len(users) == 0 {
		logrus.Info("[USER-ALL No users: ")
		c.JSON(401, gin.H{"error": "no users"})
	} else {
		logrus.Info("[USER-ALL All users: ", users)
		c.JSON(200, gin.H{"users": users})
	}
}

func Premium(c *gin.Context) {

	cookie, err := c.Cookie("token")

	if err != nil {
		logrus.Error("[USER-PREMIUM] Unauthorized: ", err)
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	claims, err := utils.ParseToken(cookie)

	if claims.Role != "admin" {
		c.JSON(401, gin.H{"error": "you are not admin", "role": claims.Role})
		return
	}

	c.JSON(200, gin.H{"success": "premium page", "role": claims.Role})
}

func Logout(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", "localhost", false, true)
	c.JSON(200, gin.H{"success": "user logged out"})
}

type Result struct {
	API   string
	Data  interface{}
	Error error
}

var apis = []string{
	"https://jsonplaceholder.typicode.com/posts/1",
	"https://jsonplaceholder.typicode.com/posts/2",
	"https://jsonplaceholder.typicode.com/posts/3",
}

func Fetch(c *gin.Context) {

	results := make(chan Result, len(apis))

	for _, api := range apis {
		go fetchData(api, results)
	}
	result := make([]Result, 0)
	for range apis {
		result = append(result, <-results)
	}
	logrus.Info("[FETCH-API] APIs are fetched")
	c.JSON(200, gin.H{"results": result})
}

func FetchFromFile(c *gin.Context) {
	urlData, err := os.ReadFile("apis.txt")
	if err != nil {
		logrus.Error("[FETCH-FROM-FILE] Error fetching from file: ", err)
		return
	}
	urls := strings.Split(string(urlData), "\n")

	data := ReadUrls(urls)
	logrus.Info("[FETCH-API] APIs are fetched")
	c.JSON(200, gin.H{"resuls": data})
}

func fetchData(api string, ch chan<- Result) {
	resp, err := http.Get(api)
	if err != nil {
		ch <- Result{API: api, Error: err}
		return
	}
	defer resp.Body.Close()

	var data interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		ch <- Result{API: api, Error: err}
		return
	}

	ch <- Result{API: api, Data: data}
}

func ReadUrls(urls []string) []string {
	jobs := make(chan string, len(urls))
	results := make(chan string, len(urls))

	for w := 1; w <= 3; w++ {
		go Worker(w, jobs, results)
	}
	for _, v := range urls {
		jobs <- v
	}
	close(jobs)
	dataFromUrls := make([]string, 0)
	for i := 1; i <= len(urls); i++ {
		dataFromUrls = append(dataFromUrls, <-results)
	}
	return dataFromUrls
}
func Worker(id int, jobs <-chan string, results chan<- string) {
	for url := range jobs {
		logrus.Println("worker", id, "started  job", url)
		resp, err := http.Get(url)
		if err != nil {
			logrus.Println("Error fetching data from", url, err)
			return
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logrus.Println("Error reading response body from", url, err)
			return
		}
		logrus.Println("worker", id, "finished job", url)
		results <- string(body)
	}
}
