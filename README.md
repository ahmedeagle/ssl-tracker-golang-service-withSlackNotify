# SSL Tracker

SSL Tracker is a simple and efficient service to monitor SSL certificates for your domains. It tracks expiration dates and sends Slack notifications before the certificates expire, ensuring you never miss a renewal.

## Features
- **Domain Monitoring**: Track SSL certificates for multiple domains.
- **Expiration Alerts**: Receive notifications on Slack before certificates expire (configurable notification period).
- **Automated Checks**: Runs checks every 24 hours by default.

## Getting Started

Follow these steps to set up and run the SSL Tracker:

### 1. Prerequisites
- **Go**: Ensure Go is installed on your system. [Download Go](https://golang.org/dl/)
- **Slack Webhook URL**: Obtain a Slack webhook URL to enable notifications. [Create a Slack Webhook](https://api.slack.com/messaging/webhooks)

### 2. Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/ssl-tracker.git
   cd ssl-tracker
Add your domains to the domains.csv file:

List all the domains you want to monitor, one domain per line.
=
example.com
another-example.com
Configure your Slack webhook in config.yml:

Add your Slack webhook URL in the config.yml file:
=
slack_webhook_url: "https://hooks.slack.com/services/your/webhook/url"
notify_days_before: 7 # Days before expiration to send notifications

3. Running the Application

Run the application using the following command:
go run main.go
The service will:

Read the domains from domains.csv.
Check SSL certificates for each domain.
Notify the configured Slack channel if any certificate is set to expire within the configured notify_days_before period.
By default, the tracker runs every 24 hours.
