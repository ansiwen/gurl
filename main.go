package main

import (
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	dbPath         = "./shortener.db"
	maxURLLength   = 2048           // A reasonable limit for URLs
	updateInterval = time.Minute    // Batch update interval for last_used timestamps
)

var (
	db *sql.DB
	templates *template.Template
	
	// For tracking accessed URLs
	accessedURLs     = make(map[string]time.Time)
	accessedURLsMu   sync.Mutex
)

func init() {
	var err error

	// Initialize random number generator
	rand.Seed(time.Now().UnixNano())

	// Connect to SQLite database
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}

	// Create table if not exists
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS urls (
			lookup_key TEXT PRIMARY KEY,
			encrypted_url BLOB,
			created_at TIMESTAMP NOT NULL,
			last_used_at TIMESTAMP
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	// Load HTML templates
	templates, err = template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatal(err)
	}
}

// Generate a short URL with 128 bits of entropy
func generateShortURL() (string, error) {
	// Generate 16 random bytes (128 bits)
	randomBytes := make([]byte, 16)
	_, err := cryptoRand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Encode to URL-safe base64
	shortURL := base64.RawURLEncoding.EncodeToString(randomBytes)
	return shortURL, nil
}

// Derive lookup key from short URL using tagged SHA-256
func deriveLookupKey(shortURL string) string {
	hash := sha256.Sum256([]byte("lookup-key" + shortURL))
	return hex.EncodeToString(hash[:])
}

// Derive encryption key from short URL using tagged SHA-256
func deriveEncryptionKey(shortURL string) []byte {
	hash := sha256.Sum256([]byte("encryption-key" + shortURL))
	return hash[:]
}

// Encrypt a URL using AES-GCM
func encryptURL(url string, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(cryptoRand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and prepend nonce
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(url), nil)
	return ciphertext, nil
}

// Decrypt a URL using AES-GCM
func decryptURL(encrypted []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Split nonce and ciphertext
	nonceSize := aesGCM.NonceSize()
	if len(encrypted) < nonceSize {
		return "", errors.New("encrypted data too short")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]

	// Decrypt
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Handler for the index page
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		handleRedirect(w, r)
		return
	}
	
	// Generate a captcha
	captcha := GenerateCaptcha()
	
	templates.ExecuteTemplate(w, "index.html", captcha)
}

// Handler for creating a short URL
func shortenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the long URL from the form
	longURL := r.FormValue("url")
	if longURL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	// Check URL length
	if len(longURL) > maxURLLength {
		http.Error(w, fmt.Sprintf("URL too long (max %d characters)", maxURLLength), http.StatusBadRequest)
		return
	}

	// Verify CAPTCHA
	captchaToken := r.FormValue("captcha_token")
	captchaAnswer := r.FormValue("captcha_answer")
	if !verifyCaptcha(captchaToken, captchaAnswer) {
		http.Error(w, "CAPTCHA verification failed", http.StatusBadRequest)
		return
	}
	
	// Check honeypot field - should be empty
	honeypot := r.FormValue("website")
	if honeypot != "" {
		// This is likely a bot, but we'll redirect to the home page instead of showing an error
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	
	// Check submission time
	formTimeStr := r.FormValue("form_time")
	formTime, err := strconv.ParseInt(formTimeStr, 10, 64)
	if err == nil {
		elapsed := time.Now().UnixMilli() - formTime
		// If form was submitted in less than 2 seconds, it's suspicious
		if elapsed < 2000 {
			log.Printf("Suspicious submission: completed too quickly (%d ms)", elapsed)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	// Generate a short URL
	shortURL, err := generateShortURL()
	if err != nil {
		http.Error(w, "Error generating short URL", http.StatusInternalServerError)
		return
	}

	// Derive lookup key and encryption key
	lookupKey := deriveLookupKey(shortURL)
	encryptionKey := deriveEncryptionKey(shortURL)

	// Encrypt the long URL
	encryptedURL, err := encryptURL(longURL, encryptionKey)
	if err != nil {
		http.Error(w, "Error encrypting URL", http.StatusInternalServerError)
		return
	}

	// Store in database with creation timestamp
	now := time.Now()
	_, err = db.Exec("INSERT INTO urls (lookup_key, encrypted_url, created_at) VALUES (?, ?, ?)", 
		lookupKey, encryptedURL, now)
	if err != nil {
		http.Error(w, "Error storing URL", http.StatusInternalServerError)
		return
	}

	// Return just the short URL (timestamp removed)
	fullShortURL := fmt.Sprintf("http://%s/%s", r.Host, shortURL)
	data := struct {
		URL string
	}{
		URL: fullShortURL,
	}
	templates.ExecuteTemplate(w, "result.html", data)
}

// Handler for redirecting short URLs
func handleRedirect(w http.ResponseWriter, r *http.Request) {
	// Extract short URL from path
	shortURL := strings.TrimPrefix(r.URL.Path, "/")
	if shortURL == "" {
		http.NotFound(w, r)
		return
	}

	// Derive lookup key and encryption key
	lookupKey := deriveLookupKey(shortURL)
	encryptionKey := deriveEncryptionKey(shortURL)

	// Query database
	var encryptedURL []byte
	err := db.QueryRow("SELECT encrypted_url FROM urls WHERE lookup_key = ?", lookupKey).Scan(&encryptedURL)
	if err != nil {
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	
	// Record this access for batch update
	accessedURLsMu.Lock()
	accessedURLs[lookupKey] = time.Now()
	accessedURLsMu.Unlock()

	// Decrypt the URL
	longURL, err := decryptURL(encryptedURL, encryptionKey)
	if err != nil {
		http.Error(w, "Error decrypting URL", http.StatusInternalServerError)
		return
	}

	// Redirect to the long URL
	http.Redirect(w, r, longURL, http.StatusFound)
}

// SimpleCaptcha represents a simple math-based captcha
type SimpleCaptcha struct {
	Question string
	Answer   string
	Token    string // For CSRF protection
}

// GenerateCaptcha creates a simple math-based captcha
func GenerateCaptcha() SimpleCaptcha {
	// Generate two random numbers between 1 and 10
	a := rand.Intn(10) + 1
	b := rand.Intn(10) + 1
	
	// Create a token that will be used to validate the captcha
	tokenBytes := make([]byte, 16)
	cryptoRand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)
	
	// Store the correct answer with the token in a secure way
	// In a real application, you'd want to use a time-limited cache or Redis
	answerKey := sha256.Sum256([]byte(token + "captcha-salt"))
	answerKeyStr := hex.EncodeToString(answerKey[:])
	storeAnswer(answerKeyStr, fmt.Sprintf("%d", a+b))
	
	return SimpleCaptcha{
		Question: fmt.Sprintf("What is %d + %d?", a, b),
		Answer:   "",  // This will be filled by the user
		Token:    token,
	}
}

// Map to store captcha answers (in a real application, use a time-limited cache)
var (
	captchaAnswers = make(map[string]string)
	captchaMu      sync.Mutex
)

// Store an answer
func storeAnswer(key, answer string) {
	captchaMu.Lock()
	defer captchaMu.Unlock()
	captchaAnswers[key] = answer
	
	// Set up a cleanup after 10 minutes
	go func(k string) {
		time.Sleep(10 * time.Minute)
		captchaMu.Lock()
		delete(captchaAnswers, k)
		captchaMu.Unlock()
	}(key)
}

// Verify a captcha response
func verifyCaptcha(token, userAnswer string) bool {
	// Regenerate the key
	answerKey := sha256.Sum256([]byte(token + "captcha-salt"))
	answerKeyStr := hex.EncodeToString(answerKey[:])
	
	captchaMu.Lock()
	defer captchaMu.Unlock()
	
	// Check if we have this token
	correctAnswer, exists := captchaAnswers[answerKeyStr]
	if !exists {
		return false
	}
	
	// Check the answer and remove the token (one-time use)
	isCorrect := correctAnswer == userAnswer
	delete(captchaAnswers, answerKeyStr)
	
	return isCorrect
}

// Updates last_used timestamps in batches
func startTimestampUpdater() {
	ticker := time.NewTicker(updateInterval)
	go func() {
		for range ticker.C {
			updateTimestamps()
		}
	}()
}

// Perform the batch update of last_used timestamps
func updateTimestamps() {
	accessedURLsMu.Lock()
	urls := make(map[string]time.Time)
	for k, v := range accessedURLs {
		urls[k] = v
	}
	// Clear the map for next batch
	accessedURLs = make(map[string]time.Time)
	accessedURLsMu.Unlock()
	
	if len(urls) == 0 {
		return // Nothing to update
	}
	
	// Begin a transaction for the batch update
	tx, err := db.Begin()
	if err != nil {
		log.Printf("Error starting transaction for timestamp updates: %v", err)
		return
	}
	
	stmt, err := tx.Prepare("UPDATE urls SET last_used_at = ? WHERE lookup_key = ?")
	if err != nil {
		log.Printf("Error preparing timestamp update statement: %v", err)
		tx.Rollback()
		return
	}
	defer stmt.Close()
	
	for key, timestamp := range urls {
		_, err := stmt.Exec(timestamp, key)
		if err != nil {
			log.Printf("Error updating timestamp for %s: %v", key, err)
			// Continue with other updates
		}
	}
	
	err = tx.Commit()
	if err != nil {
		log.Printf("Error committing timestamp updates: %v", err)
		tx.Rollback()
		return
	}
	
	log.Printf("Updated last_used timestamps for %d URLs", len(urls))
}

func main() {
	defer db.Close()

	// Start the timestamp updater
	startTimestampUpdater()

	// Set up routes
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/shorten", shortenHandler)

	// Start server
	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
