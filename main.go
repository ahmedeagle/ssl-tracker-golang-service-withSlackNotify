package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type SSLCheckResult struct {
	Domain        string `json:"domain"`
	IsValid       bool   `json:"is_valid"`
	ExpiresInDays int    `json:"expires_in_days"`
	Error         string `json:"error,omitempty"`
}

type Config struct {
	SlackWebhookURL string `yaml:"slack_webhook_url"`
	CSVFilePath     string `yaml:"csv_file_path"`
}

var (
	logger  = logrus.New()
	results []SSLCheckResult
)

// LoadConfig loads the configuration from config.yml
func LoadConfig(path string) (Config, error) {
	var config Config
	data, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return config, err
	}
	return config, nil
}

func ReadDomainsFromCSV(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	domains := make([]string, 0, len(records))
	for _, record := range records {
		if len(record) > 0 {
			domains = append(domains, record[0])
		}
	}
	return domains, nil
}

// CheckSSL checks the SSL certificate for a given domain
func CheckSSL(domain string) SSLCheckResult {
	result := SSLCheckResult{Domain: domain}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", nil)
	if err != nil {
		result.IsValid = false
		result.Error = fmt.Sprintf("failed to connect: %v", err)
		return result
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		result.IsValid = false
		result.Error = "no certificates found"
		return result
	}

	cert := certs[0]
	result.ExpiresInDays = int(cert.NotAfter.Sub(time.Now()).Hours() / 24)

	if cert.NotAfter.Before(time.Now()) {
		result.IsValid = false
		result.Error = fmt.Sprintf("certificate expired on %v", cert.NotAfter)
	} else {
		result.IsValid = true
	}

	return result
}

// SendSlackNotification sends a notification to Slack
func SendSlackNotification(webhookURL, message string) {
	payload := map[string]string{"text": message}
	jsonPayload, _ := json.Marshal(payload)

	logger.Info("==> Performing periodic SSL checks...")
	logger.Infof("%s", jsonPayload)
	dialer := &http.Client{Timeout: 10 * time.Second}
	_, err := dialer.Post(webhookURL, "application/json", bytes.NewReader(jsonPayload))
	if err != nil {
		logger.Errorf("Failed to send Slack notification: %v", err)
	}
}

// PerformChecks performs SSL checks for all domains concurrently
func PerformChecks(domains []string, slackWebhookURL string) {
	results = []SSLCheckResult{}
	var wg sync.WaitGroup
	resultsChannel := make(chan SSLCheckResult, len(domains))

	// have a seprate routine for each domain checker and block main func untill all domain completeled muli goroutine group
	for _, domain := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			resultsChannel <- CheckSSL(domain)
		}(domain)
	}

	wg.Wait()
	close(resultsChannel)

	for result := range resultsChannel {
		results = append(results, result)
		if result.Error != "" {
			logger.Warnf("Error for %s: %s", result.Domain, result.Error)
			SendSlackNotification(slackWebhookURL, fmt.Sprintf("Error for %s: %s", result.Domain, result.Error))
		} else if result.IsValid && result.ExpiresInDays <= 8 {
			SendSlackNotification(slackWebhookURL, fmt.Sprintf("Alert: %s certificate will expire in %d days", result.Domain, result.ExpiresInDays))
		}
	}
}

func main() {
	config, err := LoadConfig("config.yml")
	if err != nil {
		logger.Fatalf("Failed to load configuration: %v", err)
	}

	domains, err := ReadDomainsFromCSV(config.CSVFilePath)
	if err != nil {
		logger.Fatalf("Failed to read domains from CSV: %v", err)
	}

	// create a signal or tick so all code have this tick will be executed periodically
	ticker := time.NewTicker(24 * time.Hour)
	//ticker := time.NewTicker(10 * time.Second) // Runs every 10 seconds

	defer ticker.Stop()

	logger.Info("Starting initial SSL checks...")
	PerformChecks(domains, config.SlackWebhookURL)

	r := gin.Default()
	r.Use(gzip.Gzip(gzip.DefaultCompression))

	r.GET("/ssl-status", func(c *gin.Context) {
		c.JSON(http.StatusOK, results)
	})

	go func() {
		for range ticker.C {
			logger.Info("Performing periodic SSL checks...")
			PerformChecks(domains, config.SlackWebhookURL)
		}
	}()

	srv := &http.Server{
		Addr:    "127.0.0.1:8080",
		Handler: r,
	}

	//handle force closing the app
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	logger.Info("Shutting down server...")
	if err := srv.Shutdown(context.Background()); err != nil {
		logger.Fatalf("Server forced to shutdown: %v", err)
	}

	logger.Info("Server exiting")
}
