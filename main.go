package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/mojocn/base64Captcha"
)

const (
	dbPath         = "./shortener.db"
	maxURLLength   = 4096        // A reasonable limit for URLs
	updateInterval = time.Minute // Batch update interval for last_used timestamps
)

var (
	db        *sql.DB
	templates *template.Template

	// For tracking accessed URLs
	accessedURLs   = make(map[string]time.Time)
	accessedURLsMu sync.Mutex

	// Configure store for captcha
	captchaStore = base64Captcha.DefaultMemStore
)

func init() {
	var err error

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

// Generate a short URL with 6 random bytes (48 bits of entropy)
// which results in 8 base64 characters
func generateShortURL() (string, error) {
	// Generate 6 random bytes (48 bits)
	randomBytes := make([]byte, 6)
	_, err := rand.Read(randomBytes)
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
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
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
	captchaID, captchaB64 := GenerateCaptcha()

	data := struct {
		CaptchaID  string
		CaptchaB64 template.URL
	}{
		CaptchaID:  captchaID,
		CaptchaB64: template.URL(captchaB64),
	}

	err := templates.ExecuteTemplate(w, "index.html", data)
	if err != nil {
		http.Error(w, "Error processing template", http.StatusInternalServerError)
		log.Printf("Error processing template: %v", err)
		return
	}
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
	captchaID := r.FormValue("captcha_id")
	captchaSolution := r.FormValue("captcha_solution")
	if !captchaStore.Verify(captchaID, captchaSolution, true) {
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
		log.Printf("Error generating short URL: %v", err)
		return
	}

	// Derive lookup key and encryption key
	lookupKey := deriveLookupKey(shortURL)
	encryptionKey := deriveEncryptionKey(shortURL)

	// Encrypt the long URL
	encryptedURL, err := encryptURL(longURL, encryptionKey)
	if err != nil {
		http.Error(w, "Error encrypting URL", http.StatusInternalServerError)
		log.Printf("Error encrypting URL: %v", err)
		return
	}

	// Store in database with creation timestamp
	now := time.Now()
	_, err = db.Exec("INSERT INTO urls (lookup_key, encrypted_url, created_at) VALUES (?, ?, ?)",
		lookupKey, encryptedURL, now)
	if err != nil {
		http.Error(w, "Error storing URL", http.StatusInternalServerError)
		log.Printf("Error storing URL: %v", err)
		return
	}

	// Return the short URL
	fullShortURL := fmt.Sprintf("https://%s/%s", r.Host, shortURL)
	data := struct {
		URL string
	}{
		URL: fullShortURL,
	}
	err = templates.ExecuteTemplate(w, "result.html", data)
	if err != nil {
		http.Error(w, "Error processing template", http.StatusInternalServerError)
		log.Printf("Error processing template: %v", err)
		return
	}
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
		log.Printf("Database error: %v", err)
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
		log.Printf("Error decrypting URL: %v", err)
		return
	}

	// Redirect to the long URL
	http.Redirect(w, r, longURL, http.StatusFound)
}

// GenerateCaptcha creates an image-based captcha
func GenerateCaptcha() (string, string) {
	// Configure the captcha
	driverDigit := base64Captcha.NewDriverDigit(70, 180, 5, 0.7, 80)

	// Create the captcha and get the ID and base64 encoded PNG
	captcha := base64Captcha.NewCaptcha(driverDigit, captchaStore)
	id, b64s, answer, err := captcha.Generate()
	if err != nil {
		log.Printf("Error generating captcha: %v", err)
		// Fallback to a simple system if necessary
		return "", ""
	}

	// Store the answer
	captchaStore.Set(id, answer)

	return id, b64s
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
	urls := accessedURLs
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
