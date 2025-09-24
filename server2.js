const express = require("express");
const PDFDocument = require("pdfkit");
const nodemailer = require("nodemailer");
const path = require("path");
const cookieParser = require('cookie-parser');
const mysql = require("mysql2");
const mysql2Promise = require("mysql2/promise");
const cors = require("cors");
const bodyParser = require("body-parser");
const timeout = require("connect-timeout");
const admin = require("firebase-admin");
const morgan = require("morgan");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const axios = require("axios");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

require("dotenv").config({
  path: ".env",
});

const app = express();
const PORT = process.env.PORT;

// Razorpay Initialization
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;

// Middleware
app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ extended: true, limit: "100mb" }));
app.use(timeout("300s"));
app.use(cookieParser());
app.use(bodyParser.json({ limit: "100mb" }));
app.use(bodyParser.urlencoded({ limit: "100mb", extended: true }));
app.use(morgan("dev"));
app.use((req, res, next) => {
  if (!req.timedout) next();
});

app.use(
  cors({
    origin: [
      "https://banerjeeelectronicsconsultancyservices.com",
      "https://www.banerjeeelectronicsconsultancyservices.com",
      "https://becsofficial.com",
      "https://www.becsofficial.com",
      "http://localhost:3000",
      "http://127.0.0.1:3000",
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

// Database Configurations
const banerjeeConfig = {
  host: process.env.BN_DB_HOST,
  user: process.env.BN_DB_USER,
  password: process.env.BN_DB_PASS,
  database: process.env.BN_DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 300000,
  timeout: 300000,
  ssl: { rejectUnauthorized: false },
};

const banerjeeDB = mysql.createConnection(banerjeeConfig);
const banerjeePool = mysql.createPool({
  ...banerjeeConfig,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 10000,
  acquireTimeout: 10000,
  timeout: 10000,
});

banerjeeDB.connect((err) => {
  if (err) {
    console.error("❌ Failed to connect to Banerjee MySQL:", err.message);
  } else {
    console.log("✅ Connected to Banerjee MySQL");
  }
});

// Helper Functions
function splitName(fullName) {
  const parts = fullName.trim().split(/\s+/);
  if (parts.length === 1) {
    return { firstName: parts[0], lastName: "" };
  } else {
    const lastName = parts.pop();
    const firstName = parts.join(" ");
    return { firstName, lastName };
  }
}

async function getNextPID(connection, targetTable, prefix) {
  const [targetRows] = await connection.execute(
    `SELECT PID FROM ${targetTable} WHERE PID LIKE ? ORDER BY PID DESC LIMIT 1`,
    [`${prefix}%`]
  );

  const [allRows] = await connection.execute(
    `SELECT PID FROM All_Items WHERE PID LIKE ? ORDER BY PID DESC LIMIT 1`,
    [`${prefix}%`]
  );

  let maxNum = 0;
  if (targetRows.length > 0) {
    const num = parseInt(targetRows[0].PID.slice(1));
    if (!isNaN(num)) maxNum = Math.max(maxNum, num);
  }
  if (allRows.length > 0) {
    const num = parseInt(allRows[0].PID.slice(1));
    if (!isNaN(num)) maxNum = Math.max(maxNum, num);
  }
  const nextNum = maxNum + 1;
  return `${prefix}${nextNum.toString().padStart(3, "0")}`;
}

// Rate Limiting
const rateLimit = require("express-rate-limit");
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    status: "error",
    message: "Too many authentication attempts, please try again later",
    timestamp: new Date().toISOString(),
  },
  standardHeaders: true,
  legacyHeaders: false,
});
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    status: "error",
    message: "Too many requests, please try again later",
    timestamp: new Date().toISOString(),
  },
  standardHeaders: true,
  legacyHeaders: false,
});
const paymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: {
    status: "error",
    message: "Too many payment attempts, please try again later",
    timestamp: new Date().toISOString(),
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// app.use('/login', authLimiter);
// app.use('/signup', authLimiter);
app.use("/admin-login", authLimiter);
app.use("/api/", apiLimiter);
// app.use('/verify-payment', paymentLimiter);
// app.use('/submit-order', paymentLimiter);

app.get("/health", async (req, res) => {
  const healthcheck = {
    uptime: process.uptime(),
    message: "OK",
    timestamp: new Date().toISOString(),
  };
  res.json(healthcheck);
});

// app.get("/health/db", async (req, res) => {
//   try {
//     const banerjeeConnection = await mysql2Promise.createConnection(
//       banerjeeConfig
//     );
//     await banerjeeConnection.ping();
//     await banerjeeConnection.end();
//     const becsConnection = await becsPool.getConnection();
//     await becsConnection.ping();
//     becsConnection.release();
//     res.json({
//       status: "success",
//       message: "All database connections are healthy",
//       databases: ["Banerjee (Shop)", "BECS (Courses)"],
//       timestamp: new Date().toISOString(),
//     });
//   } catch (err) {
//     console.error("❌ Database health check failed:", err);
//     res.status(503).json({
//       status: "error",
//       message: "Database connection failed",
//       details: err.message,
//       timestamp: new Date().toISOString(),
//     });
//   }
// });

// Shop Authentication Routes (Banerjee DB)
const authenticateToken = (req, res, next) => {
  let token = null;
  
  // Debug: Check what cookies are available

  
  // Get token from cookie - FIXED: access the authToken property
  if (req.cookies && req.cookies.authToken) {
    token = req.cookies.authToken;
   
  }

  // If no cookie token, try Authorization header
  if (!token) {
    const authHeader = req.headers["authorization"];
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(" ")[1];
   
    }
  }

 

  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || 'fallback-secret-key'
    );
    req.user = decoded;
  
    next();
  } catch (error) {
    console.error('JWT Error:', error);
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token expired" });
    }
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid token" });
    }
    return res.status(403).json({ error: "Token verification failed" });
  }
};

// Sign Up
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  // Input validation
  if (!name || !email || !password) {
    return res
      .status(400)
      .json({ error: "Name, email, and password are required" });
  }

  // Email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  // Password strength validation
  if (password.length < 6) {
    return res
      .status(400)
      .json({ error: "Password must be at least 6 characters long" });
  }

  let pool;

  try {
    // Split name and handle potential errors
    const { firstName, lastName } = splitName(name);

    // Normalize email
    const normalizedEmail = email.toLowerCase().trim();

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12); // Increased salt rounds for better security

    // Create database connection pool
    pool = mysql2Promise.createPool(banerjeeConfig);

    // Check if email already exists
    const [existing] = await pool.execute(
      "SELECT email_address FROM profiles WHERE email_address = ? LIMIT 1",
      [normalizedEmail]
    );

    if (existing.length > 0) {
      return res.status(409).json({ error: "Email already exists" }); // Changed to 409 Conflict
    }

    // Insert new user - Fixed: using pool instead of connection
    // Removed created_at and account_status as they don't exist in the table
    const [insertResult] = await pool.execute(
      `INSERT INTO profiles (first_name, last_name, email_address, password)
       VALUES (?, ?, ?, ?)`,
      [firstName, lastName, normalizedEmail, hashedPassword]
    );

    // Return user data (excluding sensitive information and id)
    const user = {
      firstName,
      lastName,
      email: normalizedEmail,
    };

    res.status(201).json({
      message: "User signed up successfully",
      user,
    });
  } catch (error) {
    console.error("Signup error:", error);

    // Handle specific database errors
    if (error.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "Email already exists" });
    }

    // Handle name splitting errors
    if (error.message && error.message.includes("name")) {
      return res.status(400).json({ error: "Invalid name format" });
    }

    res.status(500).json({ error: "Internal server error" });
  } finally {
    // Ensure pool is closed properly
    if (pool) {
      await pool.end();
    }
  }
});

// login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // Input validation
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  // Email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  let pool;

  try {
    // Normalize email
    const normalizedEmail = email.toLowerCase().trim();

    // Create database connection pool
    pool = mysql2Promise.createPool(banerjeeConfig);

    // Find user by email - Removed 'id' column as it doesn't exist
    const [users] = await pool.execute(
      "SELECT first_name, last_name, email_address, password FROM profiles WHERE email_address = ? LIMIT 1",
      [normalizedEmail]
    );

    // Check if user exists
    if (users.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = users[0];

    // Validate that password hash exists
    if (!user.password) {
      console.error("User found but no password hash stored");
      return res.status(500).json({ error: "Account configuration error" });
    }

    // Compare password with hash - Ensure both values are strings
    const plainTextPassword = password.toString();
    const storedHash = user.password.toString();

    const isValidPassword = await bcrypt.compare(plainTextPassword, storedHash);

    if (!isValidPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Password is correct - Generate JWT token
    const userData = {
      firstName: user.first_name,
      lastName: user.last_name,
      email: user.email_address,
    };

    // Create JWT payload
    const jwtPayload = {
      email: user.email_address,
      firstName: user.first_name,
      lastName: user.last_name,
    };

    // Generate JWT token
    const token = jwt.sign(
      jwtPayload,
      process.env.JWT_SECRET || "your-secret-key", // Use environment variable
      {
        expiresIn: "24h", // Token expires in 24 hours
        issuer: "your-app-name",
        audience: "your-app-users",
      }
    );

    // Set HTTP-only cookie with the token
    res.cookie("authToken", token, {
      httpOnly: true, // Prevents XSS attacks
      secure: process.env.NODE_ENV === "production", // HTTPS only in production
      sameSite: "strict", // CSRF protection
      maxAge: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
    });

    // Success response with token and user data
    res.status(200).json({
      message: "Login successful",
      user: userData,
      token: token, 
      expiresIn: "24h",
    });
  } catch (error) {
    console.error("Login error:", error);

    // Handle specific database errors
    if (error.code === "ECONNREFUSED") {
      return res.status(500).json({ error: "Database connection failed" });
    }

    if (error.code === "ER_ACCESS_DENIED_ERROR") {
      return res.status(500).json({ error: "Database access denied" });
    }

    // Handle bcrypt errors
    if (error.message && error.message.includes("Invalid salt")) {
      console.error("Bcrypt error - possibly corrupted hash:", error);
      return res.status(500).json({ error: "Authentication system error" });
    }

    res.status(500).json({ error: "Internal server error" });
  } finally {
    // Properly close the pool connection
    if (pool) {
      try {
        await pool.end();
      } catch (closeError) {
        console.error("Error closing database pool:", closeError);
      }
    }
  }
});

app.post("/logout", (req, res) => {
  try {
    // Clear the authentication cookies
    res.clearCookie('authToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    res.clearCookie('userInfo', {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ error: "Logout failed" });
  }
});

// Admin Authentication Middleware
const adminAuthenticate = (req, res, next) => {
  let token = null;
  

  
  // First check for admin-specific cookie
  if (req.cookies && req.cookies.adminAuthToken) {
    token = req.cookies.adminAuthToken;
  
  }
  
  // Fallback to regular authToken cookie (in case both are used)
  if (!token && req.cookies && req.cookies.authToken) {
    token = req.cookies.authToken;
   
  }

  // Fallback to Authorization header
  if (!token) {
    const authHeader = req.headers["authorization"];
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(" ")[1];
    
    }
  }

  if (!token) {
    return res.status(401).json({ 
      success: false,
      message: "You can't access this route because you are not an admin - Authentication required" 
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
   
    
    // Check if user is admin
    if (!decoded.type || decoded.type !== 'admin') {
      return res.status(403).json({ 
        success: false,
        message: "You can't access this route because you are not an admin - Admin privileges required" 
      });
    }

    // Check if admin role exists (additional security)
    if (!decoded.role || !['admin', 'super-admin', 'moderator'].includes(decoded.role.toLowerCase())) {
      return res.status(403).json({ 
        success: false,
        message: "You can't access this route because you are not an admin - Invalid admin role" 
      });
    }

    // All checks passed - user is admin
    req.admin = decoded;
   
    next();
    
  } catch (error) {
    console.error('Admin JWT verification failed:', error.message);
    
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ 
        success: false,
        message: "You can't access this route because you are not an admin - Session expired" 
      });
    }
    
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ 
        success: false,
        message: "You can't access this route because you are not an admin - Invalid token" 
      });
    }
    
    return res.status(403).json({ 
      success: false,
      message: "You can't access this route because you are not an admin - Token verification failed" 
    });
  }
};

// admin login
app.post("/admin-login", async (req, res) => {
  const { email, password } = req.body;
  
  // Input validation
  if (!email || !password) {
    return res.status(400).json({ 
      success: false, 
      message: "Email and password are required." 
    });
  }

  // Email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ 
      success: false, 
      message: "Please provide a valid email address." 
    });
  }

  // Sanitize email
  const sanitizedEmail = email.trim().toLowerCase();

  let connection = null;

  try {
    // Create database connection
    connection = await mysql2Promise.createConnection(banerjeeConfig);

    // Get admin with only existing columns (Admin_email_id and Admin_password)
    const [rows] = await connection.execute(
      `SELECT Admin_email_id, Admin_password 
       FROM Admin 
       WHERE LOWER(Admin_email_id) = ?`,
      [sanitizedEmail]
    );

    if (rows.length === 0) {
      return res.status(401).json({ 
        success: false, 
        message: "Invalid credentials." 
      });
    }

    const admin = rows[0];

    // Password verification (supports both plain text and hashed passwords)
    let passwordValid = false;
    
    if (admin.Admin_password.startsWith('$2b$') || admin.Admin_password.startsWith('$2a$')) {
      // Hashed password
      passwordValid = await bcrypt.compare(password, admin.Admin_password);
    } else {
      // Plain text password (for backward compatibility)
      passwordValid = admin.Admin_password === password;
    }

    if (!passwordValid) {
      return res.status(401).json({ 
        success: false, 
        message: "Invalid credentials." 
      });
    }

    // Create JWT payload with default values for missing columns
    const payload = {
      adminId: admin.Admin_email_id,
      email: admin.Admin_email_id,
      name: 'Admin', // Default since Admin_name doesn't exist
      role: 'admin', // Default since Admin_role doesn't exist
      type: 'admin',
      iat: Math.floor(Date.now() / 1000)
    };

    // Generate JWT token (shorter expiry for admin security)
    const token = jwt.sign(
      payload,
      process.env.JWT_SECRET || 'your-secret-key',
      { 
        expiresIn: '8h', // 8 hours for admin sessions
        issuer: 'your-app-admin'
      }
    );

    // Set secure HTTP-only cookie for admin
    res.cookie('adminAuthToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 8 * 60 * 60 * 1000 // 8 hours
    });

    // Success response
    res.json({ 
      success: true,
      message: "Admin login successful",
      admin: {
        email: admin.Admin_email_id,
        name: 'Admin',
        role: 'admin'
      },
      token // Optional: include token in response
    });

  } catch (err) {
    console.error("💥 Error during admin login:", err);
    
    // Generic error response (don't expose internal errors)
    res.status(500).json({ 
      success: false, 
      message: "Server error." 
    });

  } finally {
    // Always close the connection
    if (connection) {
      try {
        await connection.end();
      } catch (closeError) {
        console.error('Connection close error:', closeError);
      }
    }
  }
});

// admin logout
app.post("/admin-logout", (req, res) => {
  try {
    // Clear the admin authentication cookie
    res.clearCookie('adminAuthToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/'
    });

    // Success response
    res.json({
      success: true,
      message: "Admin logged out successfully"
    });

  } catch (error) {
    console.error("Error during admin logout:", error);
    
    // Still clear the cookie even if there's an error
    res.clearCookie('adminAuthToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/'
    });

    res.json({
      success: true,
      message: "Admin logged out successfully"
    });
  }
});
// forgot password
// transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.SENDER_EMAIL,
    pass: process.env.EMAIL_PASSWORD,
  },
});
// send otp
app.post("/reset-password/sendOtp", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const connection = await mysql2Promise.createConnection(banerjeeConfig);

    // 🔹 Check if user exists
    const [rows] = await connection.execute(
      "SELECT first_name, last_name FROM profiles WHERE email_address = ?",
      [email]
    );

    if (rows.length === 0) {
      await connection.end();
      return res.status(404).json({ error: "User not found" });
    }

    // 🔹 Generate OTP
    const buffer = crypto.randomBytes(4);
    const otp = (buffer.readUInt32BE(0) % 900000) + 100000;

    // 🔹 Save OTP & expiry to DB
    await connection.execute(
      "UPDATE profiles SET reset_token = ?, reset_expires = ? WHERE email_address = ?",
      [otp, Date.now() + 3600000, email] // 1 hour expiry
    );

    await connection.end();

    // 🔹 Send email
    const mailOption = {
      from: "BECS <noreply@tathagatasenguptaventures@gmail.com>",
      to: email,
      subject: "Password Reset OTP",
      text: `You requested a password reset. Your OTP is: ${otp}`,
    };

    transporter.sendMail(mailOption, (error, info) => {
      if (error) {
        console.error("❌ Email error:", error);
        return res.status(500).json({ error: "Failed to send email" });
      }
      return res.status(200).json({ message: "OTP sent to your email" });
    });
  } catch (err) {
    console.error("❌ Reset password error:", err);
    return res.status(500).json({ error: "Server Error" });
  }
});

//check otp
app.post("/reset-password/checkOtp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    const connection = await mysql2Promise.createConnection(banerjeeConfig);

    // Find user with matching OTP and valid expiry
    const [rows] = await connection.execute(
      "SELECT email_address FROM profiles WHERE email_address = ? AND reset_token = ? AND reset_expires > ?",
      [email, otp, Date.now()]
    );

    if (rows.length === 0) {
      await connection.end();
      return res.status(400).json({ error: "OTP is invalid or has expired" });
    }

    // ✅ OTP is valid → only then clear it
    await connection.execute(
      "UPDATE profiles SET reset_token = NULL, reset_expires = NULL WHERE email_address = ? AND reset_token = ?",
      [email, otp] // ensure we only clear the matching OTP
    );

    await connection.end();

    return res.status(200).json({ message: "OTP successfully verified" });
  } catch (err) {
    console.error("❌ OTP Check Error:", err);
    return res.status(500).json({ error: "Server Error" });
  }
});

// reset password
app.post("/reset-password", async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res
        .status(400)
        .json({ error: "Email and new password are required" });
    }

    const connection = await mysql2Promise.createConnection(banerjeeConfig);

    // Find user
    const [rows] = await connection.execute(
      "SELECT email_address FROM profiles WHERE email_address = ?",
      [email]
    );

    if (rows.length === 0) {
      await connection.end();
      return res.status(400).json({ error: "User not found" });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password & clear reset_token + reset_expires
    await connection.execute(
      "UPDATE profiles SET password = ?, reset_token = NULL, reset_expires = NULL WHERE email_address = ?",
      [hashedPassword, email]
    );

    await connection.end();

    res.status(200).json({ message: "Password reset successfully" });
  } catch (err) {
    console.error("❌ Reset password error:", err);
    res.status(500).json({ error: "Server Error" });
  }
});

app.get("/get-profile",authenticateToken, async (req, res) => {
  const { email } = req.query;
  if (!email) {
    console.warn(
      `[${new Date().toISOString()}] ❌ Missing email in /get-profile request`
    );
    return res.status(400).json({
      status: "error",
      message: "Email is required.",
      timestamp: new Date().toISOString(),
    });
  }
  try {
    const conn = await mysql2Promise.createConnection(banerjeeConfig);
    const [rows] = await conn.execute(
      `SELECT 
                first_name AS firstName, 
                last_name AS lastName, 
                email_address AS email, 
                phone_number AS phone, 
                address_line_1 AS addressLine1,
                address_line_2 AS addressLine2,
                city, 
                state, 
                postal_code AS postalCode, 
                country, 
                bio
            FROM profiles
            WHERE email_address = ?`,
      [email]
    );
    await conn.end();
    if (rows.length === 0) {
      console.warn(
        `[${new Date().toISOString()}] ❌ Profile not found for email: ${email}`
      );
      return res.status(404).json({
        status: "error",
        message: "Profile not found.",
        timestamp: new Date().toISOString(),
      });
    }
    res.setHeader(
      "Cache-Control",
      "no-store, no-cache, must-revalidate, private"
    );
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.json({
      status: "success",
      profile: rows[0],
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error(
      `[${new Date().toISOString()}] ❌ Error fetching profile for email ${email}:`,
      err.message
    );
    res.status(500).json({
      status: "error",
      message: "Database error.",
      details: err.message,
      timestamp: new Date().toISOString(),
    });
  }
});

app.get("/checkout-profile",authenticateToken, async (req, res) => {
  const { email } = req.query;
  if (!email)
    return res
      .status(400)
      .json({ status: "error", message: "Email is required" });
  try {
    const conn = await mysql2Promise.createConnection(banerjeeConfig);
    const [rows] = await conn.execute(
      `SELECT 
                first_name AS firstName,
                last_name AS lastName,
                phone_number AS phone,
                address_line_1 AS addressLine1,
                address_line_2 AS addressLine2,
                city, state, postal_code AS postalCode, country
            FROM profiles
            WHERE email_address = ?`,
      [email]
    );
    await conn.end();
    if (rows.length === 0)
      return res
        .status(404)
        .json({ status: "error", message: "Profile not found" });
    res.json({ status: "success", profile: rows[0] });
  } catch (err) {
    console.error("💥 Error fetching profile:", err);
    res.status(500).json({ status: "error", message: "Database error" });
  }
});

app.post("/complete-profile",authenticateToken, async (req, res) => {
  const {
    firstName,
    lastName,
    email,
    phone,
    addressLine1,
    addressLine2 = "",
    city,
    state,
    postalCode,
    country,
    bio = "",
  } = req.body;

  if (
    !firstName ||
    !lastName ||
    !email ||
    !phone ||
    !addressLine1 ||
    !city ||
    !state ||
    !postalCode ||
    !country
  ) {
    return res.status(400).json({
      status: "error",
      message: "All required fields must be filled.",
    });
  }

  let conn;
  try {
    conn = await mysql2Promise.createConnection(banerjeeConfig);

    const [result] = await conn.execute(
      `UPDATE profiles SET 
                first_name = ?, 
                last_name = ?, 
                phone_number = ?, 
                address_line_1 = ?, 
                address_line_2 = ?, 
                city = ?, 
                state = ?, 
                postal_code = ?, 
                country = ?, 
                bio = ?
            WHERE email_address = ?`,
      [
        firstName.trim(),
        lastName.trim(),
        phone.trim(),
        addressLine1.trim(),
        addressLine2.trim(),
        city.trim(),
        state.trim(),
        postalCode.trim(),
        country.trim(),
        bio.trim(),
        email.trim(),
      ]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        status: "error",
        message: "No user updated. Email not found.",
      });
    }

    return res.status(200).json({
      status: "success",
      message: "Profile updated successfully.",
    });
  } catch (err) {
    console.error(
      `[${new Date().toISOString()}] ❌ Profile update failed:`,
      err.message
    );
    return res.status(500).json({
      status: "error",
      message: "Update failed due to server error.",
      error: err.message,
    });
  } finally {
    if (conn) await conn.end();
  }
});

// order fetch for admin
// app.get("/customer/api/orders/:orderId", async (req, res) => {
//   try {
//     const { orderId } = req.params;

//     // Convert "ORD038" -> 38 (numeric)
//     const numericOrderId = parseInt(orderId.replace(/^ORD/, ""), 10);

//     if (isNaN(numericOrderId)) {
//       return res.status(400).json({
//         message: "Invalid orderId format. Use ORDxxx or numeric ID",
//       });
//     }

//     const conn = await mysql2Promise.createConnection(banerjeeConfig);

//     // fetch order + profile info
//     const query = `
//       SELECT
//           o.order_id AS id,
//           CONCAT(p.first_name, ' ', p.last_name) AS customer,
//           p.phone_number,
//           o.delivery_date AS date,
//           o.status,
//           o.email_id,
//           p.address_line_1, p.address_line_2, p.city, p.state, p.postal_code, p.country,
//           o.pid_1, o.pid_2, o.pid_3, o.pid_4, o.pid_5,
//           o.pid_6, o.pid_7, o.pid_8, o.pid_9, o.pid_10
//       FROM Orders o
//       LEFT JOIN profiles p ON o.email_id = p.email_address
//       WHERE o.order_id = ?
//       LIMIT 1
//     `;
//     const [results] = await conn.execute(query, [numericOrderId]);

//     if (results.length === 0) {
//       await conn.end();
//       return res.status(404).json({ message: "Order not found" });
//     }

//     const order = results[0];

//     // build product list
//     const productIds = [
//       order.pid_1,
//       order.pid_2,
//       order.pid_3,
//       order.pid_4,
//       order.pid_5,
//       order.pid_6,
//       order.pid_7,
//       order.pid_8,
//       order.pid_9,
//       order.pid_10,
//     ].filter((pid) => pid);

//     let total_amount = 0;
//     let products = [];

//     for (const pid of productIds) {
//       const [itemId, quantity] = pid.split("-");
//       const [itemRows] = await conn.execute(
//         `SELECT PID, name, price, imglink AS image FROM All_Items WHERE PID = ?`,
//         [itemId]
//       );

//       if (itemRows.length > 0) {
//         const product = itemRows[0];
//         const qty = parseInt(quantity) || 1;
//         const price = parseFloat(product.price) || 0;

//         total_amount += price * qty;

//         // infer source per product
//         let source = "Unknown";
//         if (itemId.startsWith("2")) source = "Electrical";
//         else if (itemId.startsWith("1")) source = "Electronics";

//         products.push({
//           id: product.PID,
//           name: product.name,
//           image: product.image,
//           price: price.toFixed(2),
//           quantity: qty,
//           subtotal: (price * qty).toFixed(2),
//           source: source, // ✅ added per product
//         });
//       }
//     }

//     await conn.end();

//     // final order object
//     const orderDetails = {
//       id: `ORD${String(order.id).padStart(3, "0")}`,
//       customer: order.customer || "Unknown",
//       phone: order.phone_number || "",
//       date: order.date ? new Date(order.date).toISOString().split("T")[0] : "",
//       amount: total_amount.toFixed(2),
//       status: order.status,
//       email_id: order.email_id,
//       shipping_address: {
//         address_line1: order.address_line_1 || "",
//         address_line2: order.address_line_2 || "",
//         city: order.city || "",
//         state: order.state || "",
//         postal_code: order.postal_code || "",
//         country: order.country || "",
//       },
//       products: products,
//     };

//     res.json(orderDetails);
//   } catch (err) {
//     console.error("Order details error:", err);
//     res.status(500).json({
//       error: "Internal Server Error",
//       message: "An unexpected error occurred",
//       details: err.message,
//       timestamp: new Date().toISOString(),
//     });
//   }
// });

// invoice
//PDF generator

app.get("/customer/api/orders/:email/invoice/:orderId",authenticateToken, async (req, res) => {
  const { email, orderId } = req.params;

  const numericOrderId = parseInt(orderId.replace(/^ORD/, ""), 10);
  if (isNaN(numericOrderId)) {
    return res.status(400).json({ message: "Invalid orderId format" });
  }

  let pool;
  try {
    pool = mysql2Promise.createPool(banerjeeConfig);

    // Fetch order + profile
    const [results] = await pool.execute(
      `
      SELECT 
        o.order_id AS id,
        CONCAT(p.first_name, ' ', p.last_name) AS customer,
        p.phone_number,
        o.delivery_date AS date,
        o.status,
        o.email_id,
        o.amount,
        p.address_line_1, p.address_line_2, p.city, p.state, p.postal_code, p.country,
        o.cart
      FROM Orders o
      LEFT JOIN profiles p ON o.email_id = p.email_address
      WHERE o.email_id = ? AND o.order_id = ?
      LIMIT 1
      `,
      [email, numericOrderId]
    );

    if (!results.length) {
      return res.status(404).json({ message: "Order not found" });
    }

    const order = results[0];

    // Restrict invoice before delivery
    if (order.status !== "delivered") {
      return res
        .status(403)
        .json({ message: "Invoice only available after delivery" });
    }

    let cartItems = [];
    try {
      cartItems = order.cart ? JSON.parse(order.cart) : [];
    } catch (parseError) {
      console.error("❌ Error parsing cart JSON:", parseError);
      return res.status(500).json({ message: "Invalid cart data format" });
    }

    if (!Array.isArray(cartItems)) {
      return res
        .status(500)
        .json({ message: "Cart data is not in valid format" });
    }

    const products = [];

    for (const cartItem of cartItems) {
      const { id: itemId, quantity } = cartItem;

      if (!itemId || !quantity) {
        console.warn("⚠️ Skipping invalid cart item:", cartItem);
        continue;
      }

      const [itemRows] = await pool.execute(
        "SELECT PID, name, price, imglink AS image FROM All_Items WHERE PID = ? LIMIT 1",
        [itemId]
      );

      if (itemRows.length > 0) {
        const product = itemRows[0];
        const price = parseFloat(product.price) || 0;
        const qty = parseInt(quantity, 10) || 1;

        products.push({
          id: product.PID,
          name: product.name,
          image: product.image,
          price: price.toFixed(2),
          quantity: qty,
          subtotal: (price * qty).toFixed(2),
        });
      } else {
        console.warn(`⚠️ Product not found for ID: ${itemId}`);
      }
    }

    const calculatedTotal = products.reduce((sum, product) => {
      return sum + parseFloat(product.subtotal);
    }, 0);

    const invoiceOrder = {
      id: `ORD${String(order.id).padStart(3, "0")}`,
      customer: order.customer || "Unknown",
      phone: order.phone_number || "",
      date: order.date ? new Date(order.date).toISOString().split("T")[0] : "",
      amount: parseFloat(order.amount || 0).toFixed(2), // Use DB amount
      calculatedAmount: calculatedTotal.toFixed(2), // For verification
      status: order.status,
      email_id: order.email_id,
      shipping_address: {
        address_line1: order.address_line_1 || "",
        address_line2: order.address_line_2 || "",
        city: order.city || "",
        state: order.state || "",
        postal_code: order.postal_code || "",
        country: order.country || "",
      },
      products,
    };

    generateInvoice(invoiceOrder, res);
  } catch (error) {
    console.error("❌ Invoice API error:", error);
    res
      .status(500)
      .json({ error: "Internal Server Error", details: error.message });
  } finally {
    if (pool) await pool.end();
  }
});
function generateInvoice(order, res) {
  const doc = new PDFDocument({ margin: 50 });

  // ---------------- RESPONSE HEADERS ----------------
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader(
    "Content-Disposition",
    `inline; filename=invoice-${order.id}.pdf`
  );

  // ✅ Pipe only once
  doc.pipe(res);

  // ---------------- FONT ----------------
  try {
    const fontPath = path.join(process.cwd(), "fonts", "NotoSans-Regular.ttf");
    if (fs.existsSync(fontPath)) {
      doc.registerFont("NotoSans", fontPath);
      doc.font("NotoSans");
    }
  } catch (err) {
    console.error("Font load error:", err.message);
  }

  const INR = "\u20B9"; // ₹ symbol

  // ---------------- BORDER ----------------
  const drawBorder = () => {
    const pageWidth = doc.page.width;
    const pageHeight = doc.page.height;
    doc
      .rect(20, 20, pageWidth - 40, pageHeight - 40)
      .lineWidth(1.5)
      .strokeColor("#1a237e")
      .stroke();
  };
  drawBorder();
  doc.on("pageAdded", drawBorder);

  // ---------------- HEADER ----------------
  try {
    const logoPath = path.join(process.cwd(), "image", "image.png");
    if (fs.existsSync(logoPath)) {
      doc.image(logoPath, 40, 40, { width: 60 });
    }
  } catch (err) {
    console.error("Logo load error:", err.message);
  }

  const headerX = 115,
    headerY = 40;

  doc
    .fontSize(13) // smaller company heading
    .fillColor("#1a237e")
    .text(
      "BANERJEE ELECTRONICS & CONSULTANCY SERVICES (BECS)",
      headerX,
      headerY,
      { width: 400 }
    );

  doc
    .fontSize(8)
    .fillColor("#000")
    .text(
      "ADDRESS: 70/5 BANERJEE PARA ROAD, KAMALA PARK,",
      headerX,
      headerY + 14
    )
    .text("SARSUNA, KOLKATA - 700061", headerX, headerY + 24)
    .text("CONTACT NO: 9830640683", headerX, headerY + 34)
    .text("GSTIN: 19BKNPB0402R1ZZ", headerX, headerY + 44)
    .text("2ND FLOOR", headerX, headerY + 54);

  // Divider
  doc.moveDown(2);
  doc
    .moveTo(40, doc.y)
    .lineTo(doc.page.width - 40, doc.y)
    .strokeColor("#9e9e9e")
    .lineWidth(1)
    .stroke();

  // ---------------- INVOICE TITLE (PERFECTLY CENTERED) ----------------
  doc.moveDown(0.3);

  // Calculate exact center position for "INVOICE" text
  const pageWidth = doc.page.width;
  const margins = 40; // left and right margins
  const availableWidth = pageWidth - margins * 2;
  const invoiceText = "INVOICE";

  doc.fontSize(16).fillColor("#000");
  const invoiceWidth = doc.widthOfString(invoiceText);
  const invoiceX = margins + (availableWidth - invoiceWidth) / 2;

  doc.text(invoiceText, invoiceX, doc.y, { underline: true });
  doc.moveDown(0.8);

  // ---------------- ORDER DETAILS ----------------
  doc
    .fontSize(10)
    .fillColor("#1a237e")
    .text("Order Details:", 40, doc.y, { underline: true });
  doc.fillColor("#000").fontSize(9);
  const orderY = doc.y;
  doc.text(`Invoice ID: ${order.id}`, 40, orderY + 12);
  doc.text(
    `Date: ${order.date || new Date().toLocaleDateString()}`,
    40,
    orderY + 24
  );
  doc.text(`Status: ${order.status}`, 40, orderY + 36);
  doc.y = orderY + 50;

  // ---------------- CUSTOMER DETAILS ----------------
  doc
    .fontSize(10)
    .fillColor("#1a237e")
    .text("Customer Details:", 40, doc.y, { underline: true });
  doc.fillColor("#000").fontSize(9);
  const customerY = doc.y;
  doc.text(`Name: ${order.customer}`, 40, customerY + 12);
  doc.text(`Email: ${order.email_id}`, 40, customerY + 24);
  doc.text(`Phone: ${order.phone || ""}`, 40, customerY + 36);
  doc.y = customerY + 50;

  // ---------------- SHIPPING ADDRESS ----------------
  doc
    .fontSize(10)
    .fillColor("#1a237e")
    .text("Shipping Address:", 40, doc.y, { underline: true });
  const addr = order.shipping_address || {};
  doc.fillColor("#000").fontSize(9);
  const shippingY = doc.y;
  doc.text(addr.address_line1 || "", 40, shippingY + 12);
  doc.text(addr.address_line2 || "", 40, shippingY + 24);
  doc.text(`${addr.city || ""}, ${addr.state || ""}`, 40, shippingY + 36);
  doc.text(
    `${addr.postal_code || ""}, ${addr.country || ""}`,
    40,
    shippingY + 48
  );
  doc.y = shippingY + 62;

  // ---------------- PRODUCTS TABLE ----------------
  doc
    .fontSize(10)
    .fillColor("#1a237e")
    .text("Products:", 40, doc.y, { underline: true });
  doc.y += 15;

  const tableTop = doc.y;
  const itemX = 40,
    qtyX = 280,
    priceX = 350,
    subtotalX = 440;

  // Header row
  doc
    .rect(40, tableTop - 5, 510, 18)
    .fill("#eeeeee")
    .stroke();
  doc.fillColor("#000").fontSize(9);
  doc.text("Item", itemX, tableTop);
  doc.text("Qty", qtyX, tableTop);
  doc.text("Price", priceX, tableTop);
  doc.text("Subtotal", subtotalX, tableTop);

  let productTotal = 0;

  order.products.forEach((product, i) => {
    const y = tableTop + 20 + i * 18;

    if (i % 2 === 0) {
      doc
        .rect(40, y - 5, 510, 18)
        .fill("#f9f9f9")
        .stroke();
    }

    const price = parseFloat(product.price) || 0;
    const quantity = parseFloat(product.quantity) || 1;
    const subtotal = parseFloat(product.subtotal) || price * quantity;

    doc.fillColor("#000").fontSize(9);
    doc.text(product.name, itemX, y, { width: 230 });
    doc.text(quantity.toString(), qtyX, y);
    doc.text(`${INR}${price.toFixed(2)}`, priceX, y);
    doc.text(`${INR}${subtotal.toFixed(2)}`, subtotalX, y);

    productTotal += subtotal;
  });

  doc.moveDown(1.5);

  // ---------------- CALCULATIONS ----------------
  const gst = parseFloat((productTotal * 0.18).toFixed(2));
  const grandTotal = parseFloat(order.amount) || productTotal + gst;
  const delivery = parseFloat((grandTotal - (productTotal + gst)).toFixed(2));

  doc.fontSize(9).fillColor("#000");
  doc.text(`Products Total: ${INR}${productTotal.toFixed(2)}`, {
    align: "right",
  });
  doc.text(`GST (18%): ${INR}${gst.toFixed(2)}`, { align: "right" });
  doc.text(`Delivery Charges: ${INR}${delivery.toFixed(2)}`, {
    align: "right",
  });

  // ---------------- GRAND TOTAL ----------------
  doc.moveDown(0.5);
  doc
    .fontSize(12)
    .fillColor("#1a237e")
    .text(`Grand Total: ${INR}${grandTotal.toFixed(2)}`, {
      align: "right",
      underline: true,
    });

  doc.moveDown(2);

  // ---------------- FOOTER ----------------
  doc
    .moveTo(40, doc.y)
    .lineTo(doc.page.width - 40, doc.y)
    .strokeColor("#9e9e9e")
    .stroke();

  doc
    .fontSize(8)
    .fillColor("#616161")
    .text(
      "Banerjee Electronics and Consultancy Services | www.banerjeeconsultancy.com",
      { align: "center" }
    );
  doc.text("Thank you for shopping with us!", { align: "center" });

  // ✅ Finalize PDF once
  doc.end();
}

// user

// Shop Product Routes (Banerjee DB)
// app.get("/api/stock", async (req, res) => {
//   try {
//     const [results] = await becsPool.query(
//       "SELECT PID, name, category, price, imglink, description, subcat FROM stock"
//     );
//     res.setHeader("Content-Type", "application/json");
//     res.json(results);
//   } catch (err) {
//     console.error(
//       `[${new Date().toISOString()}] ❌ Error fetching stock from BECS database:`,
//       err
//     );
//     res.status(500).json({
//       error: "Failed to fetch stock",
//       details: err.message,
//       timestamp: new Date().toISOString(),
//     });
//   }
// });

// electronic item order geting route
app.get("/api/electronics", async (req, res) => {
  try {
    const conn = await mysql2Promise.createConnection(banerjeeConfig);
    const [rows] = await conn.execute(`
            SELECT 
                PID AS id,
                name,
                category,
                price,
                imglink AS image,
                description,
                subcat,
                'Electronics' AS source
            FROM Electronics_Items
        `);
    await conn.end();

    res.json({ success: true, items: rows });
  } catch (err) {
    console.error("Error fetching Electronics_Items:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// electrical item order geting route

app.get("/api/electrical-items", async (req, res) => {
  try {
    const conn = await mysql2Promise.createConnection(banerjeeConfig);
    const [rows] = await conn.execute(`
            SELECT 
                PID AS id,
                name,
                category,
                price,
                imglink AS image,
                description,
                subcat,
                'Electrical' AS source
            FROM Electrical_Items
        `);
    await conn.end();
    res.json({ success: true, items: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/customer/api/orders/email/:emailId",authenticateToken, async (req, res) => {
  let pool;
  try {
    const { emailId } = req.params;
    if (!emailId) {
      return res.status(400).json({
        status: "error",
        message: "Email ID is required",
      });
    }

    const cleanEmail = emailId.trim().toLowerCase();

    pool = mysql2Promise.createPool(banerjeeConfig);

    const [orderResults] = await pool.execute(
      `
      SELECT 
        o.order_id as id, o.status, o.email_id as email, o.amount as totalAmount, o.cart,
        p.first_name, p.last_name, p.phone_number,
        p.address_line_1, p.address_line_2, p.city, p.state, p.postal_code, p.country
      FROM Orders o
      LEFT JOIN profiles p ON LOWER(TRIM(o.email_id)) = LOWER(TRIM(p.email_address))
      WHERE LOWER(TRIM(o.email_id)) = ?
      ORDER BY o.order_id DESC
      LIMIT 1000
    `,
      [cleanEmail]
    );

    if (!orderResults.length) {
      return res.status(404).json({
        status: "error",
        message: "No orders found for this email",
      });
    }

    const allProductIds = new Set();
    orderResults.forEach((order) => {
      try {
        const cart = JSON.parse(order.cart || "[]");
        if (Array.isArray(cart)) {
          cart.forEach((item) => item.id && allProductIds.add(String(item.id)));
        }
      } catch (err) {
        console.warn(
          `Failed to parse cart for order ${order.id}:`,
          err.message
        );
      }
    });

    let productsMap = {};
    if (allProductIds.size > 0) {
      const itemIds = Array.from(allProductIds);
      const placeholders = itemIds.map(() => "?").join(",");
      const [productResults] = await pool.execute(
        `
        SELECT PID, name, price, imglink as image, category, description, subcat
        FROM All_Items
        WHERE PID IN (${placeholders})
      `,
        itemIds
      );

      productResults.forEach((product) => {
        productsMap[product.PID] = product;
      });
    }

    const processedOrders = orderResults.map((order) => {
      let cart = [];
      let calculatedTotal = 0;
      let products = [];

      try {
        cart = JSON.parse(order.cart || "[]");
        if (!Array.isArray(cart)) cart = [];
      } catch (err) {
        console.warn(
          `Failed to parse cart for order ${order.id}:`,
          err.message
        );
      }

      cart.forEach((item) => {
        const quantity = parseInt(item.quantity) || 1;
        const product = productsMap[item.id];
        if (product) {
          const price = parseFloat(product.price) || 0;
          const subtotal = price * quantity;
          calculatedTotal += subtotal;

          products.push({
            id: product.PID,
            name: product.name,
            image: product.image || "",
            price: price.toFixed(2),
            quantity,
            subtotal: subtotal.toFixed(2),
            category: product.category || "",
            source: product.PID.startsWith("2")
              ? "Electrical"
              : product.PID.startsWith("1")
              ? "Electronics"
              : "Unknown",
          });
        } else {
          products.push({
            id: item.id,
            name: "Product Not Found",
            image: "",
            price: "0.00",
            quantity,
            subtotal: "0.00",
            category: "Unknown",
            source: "Unknown",
          });
        }
      });

      const orderAmount = parseFloat(order.totalAmount) || calculatedTotal;
      const customerName =
        `${order.first_name || ""} ${order.last_name || ""}`.trim() ||
        "Guest Customer";

      return {
        id: `ORD${String(order.id).padStart(6, "0")}`,
        customer: customerName,
        email: order.email || "",
        phone: order.phone_number || "",
        status: order.status || "pending",
        amount: orderAmount.toFixed(2),
        shipping_address: {
          line_1: order.address_line_1 || "",
          line_2: order.address_line_2 || "",
          city: order.city || "",
          state: order.state || "",
          postal_code: order.postal_code || "",
          country: order.country || "India",
        },
        products,
        summary: {
          products_count: products.length,
          total_items: products.reduce((sum, p) => sum + p.quantity, 0),
          subtotal: calculatedTotal.toFixed(2),
          total: orderAmount.toFixed(2),
        },
      };
    });

    res.json({
      status: "success",
      email: cleanEmail,
      orders: processedOrders,
      summary: {
        total_orders: processedOrders.length,
        total_items: processedOrders.reduce(
          (sum, o) => sum + o.summary.total_items,
          0
        ),
        total_amount: processedOrders
          .reduce((sum, o) => sum + parseFloat(o.amount), 0)
          .toFixed(2),
      },
    });
  } catch (error) {
    console.error("Email orders fetch error:", error);
    res.status(500).json({
      status: "error",
      message: "Failed to fetch orders",
    });
  } finally {
    if (pool) await pool.end().catch(console.error);
  }
});
// create order
app.post("/create-order",authenticateToken, async (req, res) => {
  const { amount, currency } = req.body;
  if (!amount || !currency) {
    console.warn(
      `[${new Date().toISOString()}] ❌ Missing amount or currency in /create-order request`
    );
    return res.status(400).json({
      status: "error",
      message: "Amount and currency are required",
      timestamp: new Date().toISOString(),
    });
  }
  if (isNaN(amount) || amount <= 0) {
    console.warn(`[${new Date().toISOString()}] ❌ Invalid amount: ${amount}`);
    return res.status(400).json({
      status: "error",
      message: "Amount must be a positive number",
      timestamp: new Date().toISOString(),
    });
  }
  if (currency !== "INR") {
    console.warn(
      `[${new Date().toISOString()}] ❌ Unsupported currency: ${currency}`
    );
    return res.status(400).json({
      status: "error",
      message: "Only INR currency is supported",
      timestamp: new Date().toISOString(),
    });
  }
  try {
    const order = await razorpay.orders.create({
      amount: Math.round(amount),
      currency: "INR",
      receipt: `receipt_${Date.now()}`,
      payment_capture: 1,
    });
    res.json({
      status: "success",
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error(
      `[${new Date().toISOString()}] ❌ Error creating Razorpay order:`,
      err
    );
    res.status(500).json({
      status: "error",
      message: "Failed to create order",
      details: err.message,
      timestamp: new Date().toISOString(),
    });
  }
});

app.post("/verify-payment",authenticateToken, (req, res) => {
  try {
    const { razorpay_payment_id, razorpay_order_id, razorpay_signature } =
      req.body;
    if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature) {
      console.warn(
        `[${new Date().toISOString()}] ❌ Missing payment details in /verify-payment request`
      );
      return res.status(400).json({
        status: "error",
        message:
          "razorpay_payment_id, razorpay_order_id, and razorpay_signature are required",
        timestamp: new Date().toISOString(),
      });
    }
    const payload = `${razorpay_order_id}|${razorpay_payment_id}`;
    const expectedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(payload)
      .digest("hex");
    if (expectedSignature === razorpay_signature) {
      return res.json({
        status: "success",
        verified: true,
        message: "Payment verified successfully",
        timestamp: new Date().toISOString(),
      });
    } else {
      console.warn(
        `[${new Date().toISOString()}] ❌ Payment verification failed: Invalid signature`
      );
      return res.status(400).json({
        status: "error",
        verified: false,
        message: "Invalid payment signature",
        timestamp: new Date().toISOString(),
      });
    }
  } catch (error) {
    console.error(
      `[${new Date().toISOString()}] ❌ Verification error:`,
      error.message
    );
    return res.status(500).json({
      status: "error",
      message: `Server error: ${error.message}`,
      timestamp: new Date().toISOString(),
    });
  }
});

app.post("/submit-order",authenticateToken, async (req, res) => {
  const { email, cart, paymentId, orderId, signature, totalAmount } = req.body;

  // Basic validation
  if (
    !email ||
    !cart ||
    !Array.isArray(cart) ||
    !paymentId ||
    !orderId ||
    !signature ||
    !totalAmount
  ) {
    console.warn(`[${new Date().toISOString()}] ❌ Missing required fields`);
    return res.status(400).json({
      status: "error",
      message:
        "Email, cart, paymentId, orderId, signature, and totalAmount are required",
      timestamp: new Date().toISOString(),
    });
  }

  // Validate cart items
  const invalidCartItems = cart.filter(
    (item) => !item.id || !Number.isInteger(item.quantity) || item.quantity <= 0
  );
  if (invalidCartItems.length > 0) {
    console.warn(`[${new Date().toISOString()}] ❌ Invalid cart items`);
    return res.status(400).json({
      status: "error",
      message:
        "All cart items must have valid product ID and positive integer quantity",
      timestamp: new Date().toISOString(),
    });
  }

  let conn;
  try {
    conn = await mysql2Promise.createConnection(banerjeeConfig);

    // Verify email exists
    const [profileRows] = await conn.execute(
      `SELECT email_address FROM profiles WHERE email_address = ?`,
      [email]
    );
    if (profileRows.length === 0) {
      console.warn(`[${new Date().toISOString()}] ❌ Invalid email: ${email}`);
      return res.status(400).json({
        status: "error",
        message: "Invalid email: No matching profile found",
        timestamp: new Date().toISOString(),
      });
    }

    // Verify Razorpay payment signature
    const generatedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(`${orderId}|${paymentId}`)
      .digest("hex");

    if (generatedSignature !== signature) {
      console.warn(
        `[${new Date().toISOString()}] ❌ Payment verification failed for order: ${orderId}`
      );
      return res.status(400).json({
        status: "error",
        message: "Invalid payment signature",
        timestamp: new Date().toISOString(),
      });
    }

    // Insert order into Orders table
    const cartString = JSON.stringify(cart);
    const [orderResult] = await conn.execute(
      `INSERT INTO Orders (email_id, cart, status, amount) 
       VALUES (?, ?, 'pending', ?)`,
      [email, cartString, totalAmount]
    );

    // Log order summary
    const orderSummary = cart
      .map((item) => `${item.id}(qty:${item.quantity})`)
      .join(", ");
    // console.log(`[${new Date().toISOString()}] ✅ Order created: ORD${String(orderResult.insertId).padStart(3, "0")} - Items: ${orderSummary}`);

    res.json({
      status: "success",
      orderId: `ORD${String(orderResult.insertId).padStart(3, "0")}`,
      paymentId,
      items: cart.map((item) => ({
        productId: item.id,
        quantity: item.quantity,
      })),
      totalAmount,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error(
      `[${new Date().toISOString()}] ❌ Error submitting order:`,
      err
    );
    res.status(500).json({
      status: "error",
      message: "Order submission failed",
      details: err.message,
      timestamp: new Date().toISOString(),
    });
  } finally {
    if (conn) await conn.end();
  }
});

// admin
app.put("/admin/update-order-status",adminAuthenticate, async (req, res) => {
  const { id, status } = req.body;

  if (!id || !status) {
    return res.status(400).json({
      status: "error",
      message: "Order ID and new status are required",
      timestamp: new Date().toISOString(),
    });
  }

  const allowedStatuses = [
    "pending",
    "confirmed",
    "shipped",
    "delivered",
    "cancelled",
  ];
  if (!allowedStatuses.includes(status.toLowerCase())) {
    return res.status(400).json({
      status: "error",
      message: `Invalid status. Must be one of: ${allowedStatuses.join(", ")}`,
      timestamp: new Date().toISOString(),
    });
  }

  const numericOrderId = parseInt(id.replace(/^ORD/, ""));

  try {
    const conn = await mysql2Promise.createConnection(banerjeeConfig);
    const [result] = await conn.execute(
      `UPDATE Orders SET status = ? WHERE order_id = ?`,
      [status.toLowerCase(), numericOrderId]
    );

    await conn.end();

    if (result.affectedRows === 0) {
      return res.status(404).json({
        status: "error",
        message: `Order ID '${id}' not found`,
        timestamp: new Date().toISOString(),
      });
    }

    res.json({
      status: "success",
      message: `Order '${id}' status updated to '${status}'`,
      updatedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error(
      `[${new Date().toISOString()}] ❌ DB error while updating order status:`,
      err
    );
    res.status(500).json({
      status: "error",
      message: "Database error while updating order",
      details: err.message,
      timestamp: new Date().toISOString(),
    });
  }
});

const pool = mysql2Promise.createPool(banerjeeConfig);
// get all orders by admin
app.get("/api/orders",adminAuthenticate, async (req, res) => {
  try {
    const conn = await mysql2Promise.createConnection(banerjeeConfig);

    const [rows] = await conn.execute(
      `
      SELECT o.order_id, o.email_id, o.status, o.amount, o.cart,
             p.first_name, p.last_name, p.phone_number,
             p.address_line_1, p.address_line_2, p.city, p.state, p.postal_code, p.country
      FROM Orders o
      LEFT JOIN profiles p ON o.email_id = p.email_address
      ORDER BY o.order_id DESC
      `
    );

    await conn.end();

    res.json({ status: "success", orders: rows });
  } catch (err) {
    console.error("❌ Error fetching orders:", err);
    res.status(500).json({
      status: "error",
      message: "Failed to fetch orders",
      details: err.message,
      timestamp: new Date().toISOString(),
    });
  }
});

app.get("/api/orders/:email/:orderId",adminAuthenticate, async (req, res) => {
  let conn;
  try {
    const { email, orderId } = req.params;

    if (!email || !orderId || isNaN(orderId) || !email.includes("@")) {
      return res.status(400).json({
        status: "error",
        message: "Valid email and numeric order ID required",
      });
    }

    conn = await mysql2Promise.createConnection(banerjeeConfig);

    const [rows] = await conn.execute(
      `SELECT o.order_id, o.email_id, o.status, o.amount, o.cart,
              p.first_name, p.last_name, p.phone_number, 
              p.address_line_1, p.address_line_2, p.city, p.state, p.postal_code, p.country
       FROM Orders o
       LEFT JOIN profiles p ON o.email_id = p.email_address
       WHERE o.email_id = ? AND o.order_id = ?`,
      [email, orderId]
    );

    if (!rows.length) {
      return res.status(404).json({
        status: "error",
        message: "Order not found",
      });
    }

    const order = rows[0];

    let products = [];
    if (order.cart) {
      try {
        products =
          typeof order.cart === "string" ? JSON.parse(order.cart) : order.cart;
      } catch {
        products = [];
      }
    }

    const response = {
      status: "success",
      order: {
        order_id: order.order_id,
        email_id: order.email_id,
        status: order.status,
        amount: order.amount,
        customer: {
          name: `${order.first_name || ""} ${order.last_name || ""}`.trim(),
          phone: order.phone_number,
          address: {
            line_1: order.address_line_1,
            line_2: order.address_line_2,
            city: order.city,
            state: order.state,
            postal_code: order.postal_code,
            country: order.country,
          },
        },
        products,
      },
    };

    res.json(response);
  } catch (err) {
    console.error("Error fetching order:", err);
    res.status(500).json({
      status: "error",
      message: "Failed to fetch order",
    });
  } finally {
    if (conn) await conn.end().catch(console.error);
  }
});

app.get("/admin/enquiries", adminAuthenticate,async (req, res) => {
  try {
    const conn = await mysql2Promise.createConnection(banerjeeConfig);
    const [rows] = await conn.execute(`
      SELECT 
        request_id as id,
        first_name as firstName,
        last_name as lastName,
        email,
        phone,
        company as formName,
        service,
        message as rawDetails,
        submission_date as submittedAt,
        status
      FROM ConsultationRequests 
      ORDER BY submission_date DESC
    `);

    await conn.end();

    // Parse the details to separate type and actual details
    const processedRows = rows.map((row) => {
      let type = "";
      let details = row.rawDetails || "";

      // Check if details contains "Solar Type: " pattern
      const typeMatch = details.match(/Solar Type:\s*([^\n]*)/i);
      if (typeMatch) {
        type = typeMatch[1].trim();
        // Remove the solar type line from details
        details = details.replace(/Solar Type:\s*[^\n]*\n?/i, "").trim();
      }

      return {
        id: row.id,
        firstName: row.firstName,
        lastName: row.lastName,
        email: row.email,
        phone: row.phone,
        formName: row.formName,
        service: row.service,
        details: details,
        type: type,
        submittedAt: row.submittedAt,
        status: row.status,
      };
    });

    res.json(processedRows);
  } catch (err) {
    res
      .status(500)
      .json({
        success: false,
        message: "Error fetching enquiries",
        error: err.message,
      });
  }
});

// post query
app.post("/api/enquiries",adminAuthenticate ,async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      phone,
      service,
      type,
      details,
      formname,
    } = req.body;

    const conn = await mysql2Promise.createConnection(banerjeeConfig);

    // Check if user has any existing non-completed enquiries
    const [existingEnquiries] = await conn.execute(
      `SELECT request_id, status FROM ConsultationRequests 
       WHERE email = ? AND status IN ('Pending', 'In Progress')
       ORDER BY submission_date DESC
       LIMIT 1`,
      [email]
    );

    if (existingEnquiries.length > 0) {
      await conn.end();
      return res.status(400).json({
        success: false,
        message:
          "You already have a pending enquiry. Please wait for it to be completed before submitting a new one.",
        existingEnquiry: {
          id: existingEnquiries[0].request_id,
          status: existingEnquiries[0].status,
        },
      });
    }

    // Format the message more cleanly
    let message = details || "";
    if (type) {
      message = `Solar Type: ${type}\n${message}`;
    }

    // Insert new enquiry
    await conn.execute(
      `INSERT INTO ConsultationRequests 
        (first_name, last_name, email, phone, company, service, message, submission_date, status) 
       VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), 'Pending')`,
      [firstName, lastName, email, phone, formname, service, message]
    );

    await conn.end();

    res.status(201).json({
      success: true,
      message: "Enquiry submitted successfully",
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "Error saving enquiry",
      error: err.message,
    });
  }
});

// Admin: Update enquiry status
app.put("/admin/enquiries/:id/status",authenticateToken ,async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    // Check if status is provided
    if (!status) {
      return res
        .status(400)
        .json({ success: false, message: "Status is required" });
    }

    const validStatuses = ["Pending", "In Progress", "Completed"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: `Invalid status. Valid statuses are: ${validStatuses.join(
          ", "
        )}`,
        receivedStatus: status,
      });
    }

    const conn = await mysql2Promise.createConnection(banerjeeConfig);

    const [result] = await conn.execute(
      "UPDATE ConsultationRequests SET status = ? WHERE request_id = ?",
      [status, id]
    );

    await conn.end();

    if (result.affectedRows === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Enquiry not found" });
    }

    res.json({ success: true, message: "Status updated successfully" });
  } catch (err) {
    res
      .status(500)
      .json({
        success: false,
        message: "Error updating status",
        error: err.message,
      });
  }
});

app.post("/api/upload-items",adminAuthenticate ,async (req, res) => {
  const { type, items } = req.body;

  if (!type || !items || !Array.isArray(items)) {
    return res
      .status(400)
      .json({ success: false, message: "Missing type or items array." });
  }

  if (items.length > 10000) {
    return res
      .status(400)
      .json({
        success: false,
        message: "Too many items. Maximum 10000 items per upload.",
      });
  }

  const targetTable =
    type === "electronics"
      ? "Electronics_Items"
      : type === "electrical"
      ? "Electrical_Items"
      : null;
  const prefix =
    type === "electronics" ? "1" : type === "electrical" ? "2" : null;

  if (!targetTable || !prefix) {
    return res.status(400).json({ success: false, message: "Invalid type." });
  }

  let conn;
  try {
    conn = await mysql2Promise.createConnection({
      ...banerjeeConfig,
      acquireTimeout: 300000, // 5 minutes
      timeout: 300000, // 5 minutes
      reconnect: true,
      multipleStatements: true,
    });

    await conn.beginTransaction();

    await conn.execute(`DELETE FROM ${targetTable}`);
    await conn.execute(`DELETE FROM All_Items WHERE PID LIKE '${prefix}%'`);

    let currentPID = await getNextPID(conn, targetTable, prefix);

    const batchSize = 100;
    const targetTableValues = [];
    const allItemsValues = [];

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      const pid = currentPID++;

      const itemData = [
        pid,
        item.name || "",
        item.category || "",
        parseFloat(item.price) || 0,
        item.imglink || "",
        item.description || "",
        item.subcat || "",
      ];

      targetTableValues.push(itemData);
      allItemsValues.push(itemData);

      if (targetTableValues.length === batchSize || i === items.length - 1) {
        if (targetTableValues.length > 0) {
          const targetPlaceholders = targetTableValues
            .map(() => "(?, ?, ?, ?, ?, ?, ?)")
            .join(", ");
          const targetFlatValues = targetTableValues.flat();

          await conn.execute(
            `INSERT INTO ${targetTable} (PID, name, category, price, imglink, description, subcat) VALUES ${targetPlaceholders}`,
            targetFlatValues
          );

          const allItemsPlaceholders = allItemsValues
            .map(() => "(?, ?, ?, ?, ?, ?, ?)")
            .join(", ");
          const allItemsFlatValues = allItemsValues.flat();

          await conn.execute(
            `INSERT INTO All_Items (PID, name, category, price, imglink, description, subcat) VALUES ${allItemsPlaceholders}`,
            allItemsFlatValues
          );

          targetTableValues.length = 0;
          allItemsValues.length = 0;
        }
      }
    }

    await conn.commit();

    res.json({
      success: true,
      message: `Successfully processed ${items.length} items. Wiped ${targetTable}, inserted ${items.length} items, also copied to All_Items.`,
      itemsProcessed: items.length,
    });
  } catch (err) {
    console.error("Error processing upload:", err);

    if (conn) {
      try {
        await conn.rollback();
      } catch (rollbackErr) {
        console.error("Error rolling back transaction:", rollbackErr);
      }
    }

    res.status(500).json({
      success: false,
      message: "Server error during upload.",
      error: process.env.NODE_ENV === "development" ? err.message : undefined,
    });
  } finally {
    if (conn) {
      try {
        await conn.end();
      } catch (closeErr) {
        console.error("Error closing connection:", closeErr);
      }
    }
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

app.use((req, res) => {
  console.warn(
    `[${new Date().toISOString()}] ❌ 404 Not Found: ${req.method} ${
      req.originalUrl
    }`
  );
  res.status(404).json({
    status: "error",
    message: "Route not found",
    timestamp: new Date().toISOString(),
  });
});
