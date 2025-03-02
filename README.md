# IMAP Email Server

## Overview
This project is an email processing server using Node.js, Express, and Nodemailer. It supports file uploads, HMAC signature verification, access control, secure email sending via SMTP, and protection against spam and injection attacks. The server can be deployed manually or using Docker.

## Technology Stack
- **Node.js 18** – Runtime environment
- **Express** – Web framework
- **Multer** – File upload handling (supports `multipart/form-data` for PDF attachments)
- **Nodemailer** – Email sending
- **dotenv** – Environment variables management
- **CryptoJS** – HMAC signature verification
- **Docker & Docker Compose** – Containerization
- **Security Features** – Protection against SQL injection, XSS, and spam prevention

## Environment Variables
The application uses an `.env.local` file for configuration. Example:

```ini
PORT="8497"
SECRET_KEY="your_secret_key_here"
SMTP_HOST="smtp.example.com"
SMTP_PORT="587"
SMTP_SECURE="false"
SMTP_USER="your_email@example.com"
SMTP_PASS="your_password"
```

Ensure this file is placed inside the `imapserver` directory.

## Cryptography: HMAC Signature Verification
The server validates incoming requests using HMAC SHA-256 signatures. Each request must include:
- `data` (JSON payload)
- `timestamp` (Unix timestamp)
- `signature` (HMAC hash)

### Signature Generation
To create a valid signature:
```js
const CryptoJS = require("crypto-js");
const payload = JSON.stringify({ data: yourData, timestamp: yourTimestamp });
const signature = CryptoJS.HmacSHA256(payload, process.env.SECRET_KEY).toString();
```

## Installation & Setup
### Manual Installation
1. **Clone the repository**
   ```sh
   git clone https://github.com/your-repo/imap-email-server.git
   cd imap-email-server/imapserver
   ```
2. **Install dependencies**
   ```sh
   npm install
   ```
3. **Start the server**
   ```sh
   npm start
   ```

### Deploying with Docker
1. **Build and start the container**
   ```sh
   docker-compose up --build -d
   ```
2. **Check logs**
   ```sh
   docker logs -f swiss-backend
   ```
3. **Stop the container**
   ```sh
   docker-compose down
   ```

## API Endpoints
### Send Email
**Endpoint:** `POST /send-email`

**Content-Type:** `multipart/form-data`

**Request Body:**
```json
{
  "to": "recipient@example.com",
  "cc": "cc@example.com",
  "subject": "Test Email",
  "text": "Hello, this is a test email.",
  "data": "{\"firstName\": \"John\", \"lastName\": \"Doe\"}",
  "timestamp": "1700000000",
  "signature": "generated_hmac_signature",
  "pdf": "<attached file>"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Email sent!"
}
```

## Security Features
- **HMAC Signature Verification**: Prevents unauthorized API access.
- **Access Control**: Restricts API usage based on IP and Origin headers.
- **Request Expiry Check**: Prevents replay attacks.
- **Input Validation**: Protects against SQL injections and invalid data formats.
- **Spam Prevention**: Blocks mass email sending from unauthorized sources.

## Contributing
Feel free to submit issues or pull requests to improve the project.

## License
This project is licensed under the MIT License.

