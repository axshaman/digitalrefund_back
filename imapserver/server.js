import express from "express";
import multer from "multer";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import CryptoJS from "crypto-js";

dotenv.config();

const app = express();
const upload = multer({ limits: { fileSize: 5 * 1024 * 1024 } }); // Limit: 5MB
const PORT = process.env.PORT || 8497;
const SECRET_KEY = process.env.SECRET_KEY || "default_secret_key";
const REQUEST_TIMEOUT = 5 * 60 * 1000; // 5 minutes

// 🔧 Support for JSON and form-urlencoded
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 📌 HMAC signature verification with logs
const verifySignature = (data, timestamp, signature) => {
  console.log("🔍 [HMAC] Verifying signature...");

  // Convert timestamp to number
  const parsedTimestamp = Number(timestamp);

  // Parse data if it's a string
  let parsedData;
  try {
    parsedData = typeof data === "string" ? JSON.parse(data) : data;
  } catch (error) {
    console.error("❌ [HMAC] Error parsing data:", error);
    return false;
  }

  // Sort keys before JSON.stringify()
  const sortedKeys = Object.keys(parsedData).sort();
  const sortedData = JSON.stringify(
    { data: sortedKeys.reduce((obj, key) => ({ ...obj, [key]: parsedData[key] }), {}), timestamp: parsedTimestamp }
  );

  // Generate expected signature
  const expectedSignature = CryptoJS.HmacSHA256(sortedData, SECRET_KEY).toString();

  console.log("   - Expected signature:", expectedSignature);
  console.log("   - Signatures match?", expectedSignature === signature ? "✅ Yes" : "❌ No");

  return expectedSignature === signature;
};

// 🔧 Access control (IP and Origin)
app.use((req, res, next) => {
  const allowedOrigins = ["https://swiss-lawsuit.info"];
  const allowedIPs = ["185.209.228.173", "127.0.0.1", "172.", "192.168."];

  let clientIP = req.ip || req.connection.remoteAddress;
  if (clientIP.includes("::ffff:")) clientIP = clientIP.split("::ffff:")[1];

  console.log(`🔍 [ACCESS] Checking access for IP: ${clientIP}`);

  if (!allowedIPs.some((ip) => clientIP.startsWith(ip))) {
    console.error(`❌ [ACCESS] Access denied for IP ${clientIP}`);
    return res.status(403).json({ error: "Forbidden: Unauthorized IP" });
  }

  const origin = req.headers.origin || req.headers.referer;
  console.log("🔍 [ACCESS] Checking Origin:", origin);

  if (origin && !allowedOrigins.includes(origin)) {
    console.error(`❌ [ACCESS] Unauthorized request origin, expected: ${allowedOrigins}`);
    return res.status(403).json({ error: "Forbidden: Invalid Origin" });
  }

  next();
});

// 📌 CSP security headers
app.use((req, res, next) => {
  console.log("🔍 [SECURITY] Setting up CSP");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none';"
  );
  next();
});

// 🚀 SMTP configuration
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// 📩 Email sending route
app.post("/send-email", upload.single("pdf"), async (req, res) => {
  console.log("📩 [EMAIL] Received email send request");
  console.log("   - Request data:", JSON.stringify(req.body, null, 2));

  const { to, cc, subject, text, data, timestamp, signature } = req.body;
  const pdfFile = req.file;

  // Validate required parameters
  if (!to || !subject || !text || !data || !timestamp || !signature) {
    console.error("❌ [EMAIL] Error: Missing required parameters");
    return res.status(400).json({ error: "Missing email parameters" });
  }

  // HMAC signature verification
  if (!verifySignature(data, timestamp, signature)) {
    console.error("❌ [EMAIL] Error: Invalid HMAC signature");
    return res.status(403).json({ error: "Invalid signature" });
  }

  // Request expiration check
  if (Date.now() - Number(timestamp) > REQUEST_TIMEOUT) {
    console.error("❌ [EMAIL] Error: Request expired");
    return res.status(403).json({ error: "Request expired" });
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(to)) {
    console.error("❌ [EMAIL] Error: Invalid email format");
    return res.status(400).json({ error: "Invalid email format" });
  }

  // Parse JSON from `data`
  let messageData;
  try {
    if (typeof data === "string" && data.trim().startsWith("{")) {
      messageData = JSON.parse(data);
    } else {
      throw new Error("Invalid JSON format in `data`");
    }
    console.log("📩 [EMAIL] Decoded data:", messageData);
  } catch (error) {
    console.error("❌ [EMAIL] Error: Invalid JSON in `data`", error);
    return res.status(400).json({ error: "Invalid JSON format in `data`" });
  }

  // 📩 Generate HTML email template
const emailHtml = `
  <html>
  <body style="font-family: Arial, sans-serif; color: #2c3e50;">
    <h2 style="color: #3498db;">Class-Action Lawsuit Notification</h2>
    <p><strong>Dear ${messageData.firstName || "User"},</strong></p>
    <p>Your request for the class-action lawsuit has been received.</p>
    
    <h3 style="color: #34495e;">Submission Details</h3>
    <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse; width: 100%;">
      <tr style="background-color: #ecf0f1;">
        <th align="left">Field</th>
        <th align="left">Value</th>
      </tr>
      <tr><td><strong>First Name</strong></td><td>${messageData.firstName || "N/A"}</td></tr>
      <tr><td><strong>Last Name</strong></td><td>${messageData.lastName || "N/A"}</td></tr>
      <tr><td><strong>Email</strong></td><td>${messageData.email || "N/A"}</td></tr>
      <tr><td><strong>Phone</strong></td><td>${messageData.phone || "N/A"}</td></tr>
      <tr><td><strong>Travel Date</strong></td><td>${messageData.travelDate || "N/A"}</td></tr>
      <tr><td><strong>Booking Reference</strong></td><td>${messageData.bookingReference || "N/A"}</td></tr>
      <tr><td><strong>Directly Affected</strong></td><td>${messageData.isDirectlyAffected ? "Yes" : "No"}</td></tr>
      ${messageData.isDirectlyAffected ? `
        <tr><td><strong>Incident Type</strong></td><td>${messageData.incidentType || "N/A"}</td></tr>
        <tr><td><strong>Incident Description</strong></td><td>${messageData.incidentDescription || "N/A"}</td></tr>
        <tr><td><strong>Has Evidence</strong></td><td>${messageData.hasEvidence ? "Yes" : "No"}</td></tr>
      ` : ""}
      <tr><td><strong>Agreed to Terms</strong></td><td>${messageData.agreeToTerms ? "Yes" : "No"}</td></tr>
    </table>

    <p>We will review your submission and contact you if any additional information is required.</p>
    <p>Thank you,<br/> Team of the project "People VS Swiss Air"<br/>
    <a href="https://www.swiss-lawsuit.info">www.swiss-lawsuit.info</a></p>
  </body>
  </html>
`;

  try {
    const mailOptions = {
      from: `"Class Lawsuits" <${process.env.SMTP_USER}>`,
      to,
      cc,
      subject,
      text,
      html: emailHtml,
      attachments: pdfFile ? [{ filename: pdfFile.originalname, content: pdfFile.buffer }] : [],
    };

    console.log("📨 [EMAIL] Sending email to:", to);
    await transporter.sendMail(mailOptions);
    console.log("✅ [EMAIL] Email successfully sent!");

    res.json({ success: true, message: "Email sent!" });
  } catch (error) {
    console.error("❌ [EMAIL] Error sending email:", error);
    res.status(500).json({ error: "Email not sent", details: error.message });
  }
});

// 🚀 Start the server
app.listen(PORT, () => {
  console.log(`📩 [SERVER] Email server running on port ${PORT}`);
});
