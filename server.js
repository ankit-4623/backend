const express = require("express");
const PDFDocument = require("pdfkit");
const nodemailer = require("nodemailer");
const path = require('path')
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

require("dotenv").config({
   path: '.env'
});

const app = express();
const PORT = process.env.PORT;

// Razorpay Initialization
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret:process.env.RAZORPAY_KEY_SECRET,
});

const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;

// Middleware
app.use(
  cors({
    origin: [
      "https://banerjeeelectronicsconsultancyservices.com",
      "https://www.banerjeeelectronicsconsultancyservices.com",
      "http://localhost:3000",
      "http://127.0.0.1:3000",
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

// Handle preflight requests globally
// app.options('*', cors());


app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(timeout('300s'));
app.use(bodyParser.json({ limit: "100mb" }));
app.use(bodyParser.urlencoded({ limit: "100mb", extended: true }));
app.use(morgan("dev"));
app.use((req, res, next) => {
  if (!req.timedout) next();
});

// Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  if (req.body && Object.keys(req.body).length > 0) {
    // console.log('Request Body:', JSON.stringify(req.body, null, 2));
  }
  next();
});

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

const becsConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER ,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 300000,
  ssl: { rejectUnauthorized: false },
};

// MySQL Connections
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

const becsPool = mysql2Promise.createPool(becsConfig);

banerjeeDB.connect((err) => {
  if (err) {
    console.error("❌ Failed to connect to Banerjee MySQL:", err.message);
  }
});

becsPool
  .getConnection()
  .then((connection) => {
    connection.release();
  })
  .catch((error) => {
    console.error("❌ BECS MySQL connection failed:", error);
  });

// Firebase Admin Initialization
try {
  const serviceAccount = require("./firebase-service-account.json");
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL:
      process.env.FIREBASE_DATABASE_URL,
  });
} catch (error) {
  console.warn(
    "⚠️ Firebase Admin initialization failed (optional for shop features):",
    error.message
  );
}

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

async function authenticateFirebaseToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : null;
    if (!token) {
      console.warn("❌ No token provided");
      return res.status(401).json({
        error: "Unauthorized",
        message: "No authentication token provided",
        timestamp: new Date().toISOString(),
      });
    }
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (err) {
    console.error("❌ Token verification failed:", err.message);
    res.status(403).json({
      error: "Forbidden",
      message: "Invalid or expired authentication token",
      timestamp: new Date().toISOString(),
    });
  }
}

async function authenticateTeacher(req, res, next) {
  const teacherIdRaw = req.headers["x-teacher-id"];
  const { teacher_id: teacherIdParamRaw } = req.params;
  const teacherId = parseInt(teacherIdRaw);
  const teacherIdParam = parseInt(teacherIdParamRaw);

  if (isNaN(teacherId) || teacherId <= 0) {
    console.warn(`❌ Invalid teacher ID in header: ${teacherIdRaw}`);
    return res.status(400).json({
      status: "error",
      message:
        "Invalid Teacher ID in X-Teacher-ID header; must be a positive integer",
      timestamp: new Date().toISOString(),
    });
  }
  if (teacherId !== teacherIdParam) {
    console.warn(
      `❌ Teacher ID mismatch: header(${teacherId}) vs requested(${teacherIdParam})`
    );
    return res.status(403).json({
      status: "error",
      message: "You can only access your own resources",
      timestamp: new Date().toISOString(),
    });
  }
  try {
    const [results] = await becsPool.query(
      `SELECT teacher_id FROM teachers WHERE teacher_id = ?`,
      [teacherId]
    );
    if (results.length === 0) {
      console.warn(`❌ Invalid teacher ID: ${teacherId}`);
      return res.status(401).json({
        status: "error",
        message: "Invalid teacher ID",
        timestamp: new Date().toISOString(),
      });
    }
    req.teacher = { teacher_id: teacherId };
    next();
  } catch (err) {
    console.error("❌ Error verifying teacher ID:", err);
    res.status(500).json({
      status: "error",
      message: "Failed to verify teacher ID",
      timestamp: new Date().toISOString(),
    });
  }
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
app.use("/api/teacher/login", authLimiter);
app.use("/api/", apiLimiter);
// app.use('/verify-payment', paymentLimiter);
// app.use('/submit-order', paymentLimiter);

// Main Routes
app.get("/", (req, res) => {
  res.json({
    status: "live",
    message: "🔥 Combined Backend Server is Live!",
    services: ["Shop Management", "Course Management", "Payment Processing"],
    timestamp: new Date().toISOString(),
  });
});

app.get("/health", async (req, res) => {
  const healthcheck = {
    uptime: process.uptime(),
    message: "OK",
    timestamp: new Date().toISOString(),
  };
  res.json(healthcheck);
});

app.get("/health/db", async (req, res) => {
  try {
    const banerjeeConnection = await mysql2Promise.createConnection(
      banerjeeConfig
    );
    await banerjeeConnection.ping();
    await banerjeeConnection.end();
    const becsConnection = await becsPool.getConnection();
    await becsConnection.ping();
    becsConnection.release();
    res.json({
      status: "success",
      message: "All database connections are healthy",
      databases: ["Banerjee (Shop)", "BECS (Courses)"],
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("❌ Database health check failed:", err);
    res.status(503).json({
      status: "error",
      message: "Database connection failed",
      details: err.message,
      timestamp: new Date().toISOString(),
    });
  }
});

const cheerio = require("cheerio");

app.get("/api/proxy-pdf", async (req, res) => {
  const { url } = req.query;
  if (!url) {
    return res.status(400).json({
      status: "error",
      message: "PDF URL is required",
      timestamp: new Date().toISOString(),
    });
  }
  try {
    const response = await axios.get(url, {
      responseType: "arraybuffer",
      headers: { Accept: "application/pdf" },
      maxRedirects: 5,
      timeout: 15000,
    });
    if (response.headers["content-type"].includes("application/pdf")) {
      res.set({
        "Content-Type": "application/pdf",
        "Content-Length": response.headers["content-length"],
        "Cache-Control": "no-cache",
      });
      res.send(response.data);
    } else {
      throw new Error("The URL does not point to a valid PDF file.");
    }
  } catch (error) {
    console.error(
      `[${new Date().toISOString()}] ❌ Error proxying PDF:`,
      error.message
    );
    res.status(500).json({
      status: "error",
      message: error.message || "Failed to fetch PDF",
      timestamp: new Date().toISOString(),
    });
  }
});

// Shop Authentication Routes (Banerjee DB)
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res
      .status(400)
      .json({ error: "Name, email, and password are required." });
  }
  const { firstName, lastName } = splitName(name);
  try {
    const connection = await mysql2Promise.createConnection(banerjeeConfig);
    const query = `
            INSERT INTO profiles
            (first_name, last_name, email_address, phone_number, password, address_line_1, address_line_2, city, state, postal_code, country, bio)
            VALUES (?, ?, ?, '', ?, '', '', '', '', '', '', '')
        `;
    await connection.execute(query, [firstName, lastName, email, password]);
    await connection.end();
    res.json({ message: "User signed up successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Database error" });
  }
});
// login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    // console.log('❌ Missing email or password');
    return res.status(400).json({
      status: "error",
      message: "Email and Password are required.",
    });
  }
  try {
    const connection = await mysql2Promise.createConnection(banerjeeConfig);
    const [rows] = await connection.execute(
      "SELECT first_name, last_name, password FROM profiles WHERE email_address = ?",
      [email]
    );
    await connection.end();
    if (rows.length === 0) {
      // console.log('⚠️ Email not found');
      return res.status(200).json({ status: "not_found" });
    }
    const user = rows[0];
    if (user.password !== password) {
      // console.log('❌ Incorrect password');
      return res.status(200).json({ status: "wrong_password" });
    }
    return res.status(200).json({
      status: "success",
      email,
      firstName: user.first_name,
      lastName: user.last_name,
    });
  } catch (err) {
    console.error("💥 Error during login:", err);
    return res.status(500).json({
      status: "error",
      message: "Server error.",
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
app.post('/reset-password/sendOtp', async (req, res) => {
  try {
    const { email } = req.body;

    // 🔹 Validate input
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
      [otp, Date.now() + 3600000, email]  // 1 hour expiry
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
app.post('/reset-password/checkOtp', async (req, res) => {
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
      [email, otp]   // ensure we only clear the matching OTP
    );

    await connection.end();

    return res.status(200).json({ message: "OTP successfully verified" });

  } catch (err) {
    console.error("❌ OTP Check Error:", err);
    return res.status(500).json({ error: "Server Error" });
  }
});

// reset password
app.post('/reset-password',async(req,res)=>{
 try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({ error: "Email and new password are required" });
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
    // const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password & clear reset_token + reset_expires
    await connection.execute(
      "UPDATE profiles SET password = ?, reset_token = NULL, reset_expires = NULL WHERE email_address = ?",
      [newPassword, email]
    );

    await connection.end();

    res.status(200).json({ message: "Password reset successfully" });
  } catch (err) {
    console.error("❌ Reset password error:", err);
    res.status(500).json({ error: "Server Error" });
  }
})


app.post("/admin-login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res
      .status(400)
      .json({ success: false, message: "Email and password are required." });
  }
  try {
    const conn = await mysql2Promise.createConnection(banerjeeConfig);
    const [rows] = await conn.execute(
      `SELECT Admin_email_id, Admin_password FROM Admin WHERE Admin_email_id = ?`,
      [email]
    );
    await conn.end();
    if (rows.length === 0) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials." });
    }
    const admin = rows[0];
    if (admin.Admin_password !== password) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials." });
    }
    res.json({ success: true });
  } catch (err) {
    console.error("💥 Error during admin login:", err);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

// Shop Profile Management Routes (Banerjee DB)
app.get("/get-profile", async (req, res) => {
  const { email } = req.query;
  if (!email) {
    console.warn(
      `[${new Date().toISOString()}] ❌ Missing email in /get-profile request`
    );
    return res
      .status(400)
      .json({
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
      return res
        .status(404)
        .json({
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
    res
      .status(500)
      .json({
        status: "error",
        message: "Database error.",
        details: err.message,
        timestamp: new Date().toISOString(),
      });
  }
});

app.get("/checkout-profile", async (req, res) => {
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

app.post("/complete-profile", async (req, res) => {
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
 // <-- your PDF generator

app.get("/customer/api/orders/:email/invoice/:orderId", async (req, res) => {
  try {
    const { email, orderId } = req.params;

    // Convert "ORD038" -> 38 (numeric)
    const numericOrderId = parseInt(orderId.replace(/^ORD/, ""), 10);

    if (isNaN(numericOrderId)) {
      return res.status(400).json({
        message: "Invalid orderId format. Use ORDxxx or numeric ID",
      });
    }

    const conn = await mysql2Promise.createConnection(banerjeeConfig);

    // fetch order + profile info
    const query = `
      SELECT 
          o.order_id AS id, 
          CONCAT(p.first_name, ' ', p.last_name) AS customer,
          p.phone_number,
          o.delivery_date AS date,
          o.status,
          o.email_id,
          p.address_line_1, p.address_line_2, p.city, p.state, p.postal_code, p.country,
          o.pid_1, o.pid_2, o.pid_3, o.pid_4, o.pid_5,
          o.pid_6, o.pid_7, o.pid_8, o.pid_9, o.pid_10
      FROM Orders o
      LEFT JOIN profiles p ON o.email_id = p.email_address
      WHERE o.email_id = ? AND o.order_id = ?
      LIMIT 1
    `;
    const [results] = await conn.execute(query, [email, numericOrderId]);

    if (results.length === 0) {
      await conn.end();
      return res.status(404).json({ message: "Order not found" });
    }

    const order = results[0];

    // build product list
    const productIds = [
      order.pid_1,
      order.pid_2,
      order.pid_3,
      order.pid_4,
      order.pid_5,
      order.pid_6,
      order.pid_7,
      order.pid_8,
      order.pid_9,
      order.pid_10,
    ].filter((pid) => pid);

    let total_amount = 0;
    let products = [];

    for (const pid of productIds) {
      const [itemId, quantity] = pid.split("-");
      const [itemRows] = await conn.execute(
        `SELECT PID, name, price, imglink AS image FROM All_Items WHERE PID = ?`,
        [itemId]
      );
      if (itemRows.length > 0) {
        const product = itemRows[0];
        const qty = parseInt(quantity) || 1;
        const price = parseFloat(product.price) || 0;

        total_amount += price * qty;

        products.push({
          id: product.PID,
          name: product.name,
          image: product.image,
          price: price.toFixed(2),
          quantity: qty,
          subtotal: (price * qty).toFixed(2),
        });
      }
    }

    await conn.end();

    // Invoice only after delivery
    if (order.status !== "delivered") {
      return res.status(403).json({
        message: "Invoice only available after delivery",
      });
    }

    // final invoice object
    const invoiceOrder = {
      id: `ORD${String(order.id).padStart(3, "0")}`,
      customer: order.customer || "Unknown",
      phone: order.phone_number || "",
      date: order.date ? new Date(order.date).toISOString().split("T")[0] : "",
      amount: total_amount.toFixed(2),
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
      products: products,
    };

    // generate PDF invoice
    generateInvoice(invoiceOrder, res);
  } catch (err) {
    console.error("Invoice error:", err);
    res.status(500).json({
      error: "Internal Server Error",
      message: "An unexpected error occurred",
      details: err.message,
      timestamp: new Date().toISOString(),
    });
  }
});

// pdf formate

function generateInvoice(order, res) {
  const doc = new PDFDocument({ margin: 50 });

  // ✅ Load a font that supports ₹ symbol (NotoSans/DejaVuSans/etc.)
  const fontPath = path.join(process.cwd(), "fonts", "NotoSans-Regular.ttf");
  doc.registerFont("NotoSans", fontPath);
  doc.font("NotoSans");

  const INR = "\u20B9"; // Unicode for ₹ symbol

  res.setHeader(
    "Content-Disposition",
    `attachment; filename=invoice-${order.id}.pdf`
  );
  res.setHeader("Content-Type", "application/pdf");

  doc.pipe(res);

  // --- Company Header ---
  doc
    .fontSize(18)
    .text("Banerjee Electronics and Consultancy Services", {
      align: "center",
      underline: true,
    });
  doc.moveDown();

  // --- Invoice Header ---
  doc.fontSize(20).text("Invoice", { align: "center" });
  doc.moveDown();

  // --- Order info ---
  doc.fontSize(12).text(`Invoice ID: ${order.id}`);
  doc.text(`Date: ${order.date || new Date().toLocaleDateString()}`);
  doc.text(`Status: ${order.status}`);
  doc.moveDown();

  // --- Customer details ---
  doc.fontSize(14).text("Customer Details:", { underline: true });
  doc
    .fontSize(12)
    .text(`Name: ${order.customer}`)
    .text(`Email: ${order.email_id}`)
    .text(`Phone: ${order.phone || ""}`);
  doc.moveDown();

  // --- Shipping address ---
  doc.fontSize(14).text("Shipping Address:", { underline: true });
  const addr = order.shipping_address || {};
  doc
    .fontSize(12)
    .text(addr.address_line1 || "")
    .text(addr.address_line2 || "")
    .text(`${addr.city || ""}, ${addr.state || ""}`)
    .text(`${addr.postal_code || ""}, ${addr.country || ""}`);
  doc.moveDown();

  // --- Products Table ---
  doc.fontSize(14).text("Products:", { underline: true });
  doc.moveDown(0.5);

  const tableTop = doc.y;
  const itemX = 50;
  const qtyX = 300;
  const priceX = 370;
  const subtotalX = 450;

  doc.fontSize(12).text("Item", itemX, tableTop);
  doc.text("Qty", qtyX, tableTop);
  doc.text("Price", priceX, tableTop);
  doc.text("Subtotal", subtotalX, tableTop);

  doc.moveDown();

  order.products.forEach((product, i) => {
    const y = tableTop + 25 + i * 20;
    doc.fontSize(12).text(product.name, itemX, y, { width: 240 });
    doc.text(product.quantity.toString(), qtyX, y);
    doc.text(`${INR}${product.price}`, priceX, y);
    doc.text(`${INR}${product.subtotal}`, subtotalX, y);
  });

  doc.moveDown(2);

  // --- Total ---
  doc.fontSize(14).text(`Grand Total: ${INR}${order.amount}`, {
    align: "right",
  });
  doc.moveDown(2);

  // --- Footer ---
  doc.fontSize(12).text("Thank you for your purchase!", {
    align: "center",
  });

  doc.end();
}


// Shop Product Routes (Banerjee DB)
app.get("/api/stock", async (req, res) => {
  try {
    const [results] = await becsPool.query(
      "SELECT PID, name, category, price, imglink, description, subcat FROM stock"
    );
    res.setHeader("Content-Type", "application/json");
    res.json(results);
  } catch (err) {
    console.error(
      `[${new Date().toISOString()}] ❌ Error fetching stock from BECS database:`,
      err
    );
    res.status(500).json({
      error: "Failed to fetch stock",
      details: err.message,
      timestamp: new Date().toISOString(),
    });
  }
});

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

// Shop Order Management Routes (Banerjee DB)
app.post("/create-order", async (req, res) => {
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

// update order status
app.put("/admin/update-order-status", async (req, res) => {
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

app.post("/verify-payment", (req, res) => {
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

app.post("/submit-order", async (req, res) => {
  const { email, cart, paymentId, orderId, signature, totalAmount } = req.body;
  
  // Quick validation
  if (!email || !Array.isArray(cart) || !paymentId || !orderId || !signature || !totalAmount) {
    return res.status(400).json({
      status: "error",
      message: "All fields are required"
    });
  }

  const conn = await mysql2Promise.createConnection(banerjeeConfig);
  
  try {
    // Verify email exists
    const [profileRows] = await conn.execute(
      "SELECT email_address FROM profiles WHERE email_address = ?",
      [email]
    );
    
    if (profileRows.length === 0) {
      return res.status(400).json({
        status: "error",
        message: "Invalid email"
      });
    }

    // Verify payment signature
    const generatedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(`${orderId}|${paymentId}`)
      .digest("hex");

    if (generatedSignature !== signature) {
      return res.status(400).json({
        status: "error",
        message: "Invalid payment signature"
      });
    }

    // Insert order with amount
    const [orderResult] = await conn.execute(
      "INSERT INTO Orders (email_id, amount, status) VALUES (?, ?, 'completed')",
      [email, totalAmount]
    );

    res.json({
      status: "success",
      orderId: `ORD${String(orderResult.insertId).padStart(3, "0")}`,
      paymentId
    });

  } catch (error) {
    res.status(500).json({
      status: "error",
      message: "Order submission failed"
    });
  } finally {
    await conn.end();
  }
});

const pool = mysql2Promise.createPool(banerjeeConfig);

 app.get("/api/orders", async (req, res) => {
  let conn;
  try {
    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;
    
    // Optional filters
    const status = req.query.status;
    const search = req.query.search;
    
    conn = await pool.getConnection();

    // Build WHERE clause for filters
    let whereClause = '';
    let queryParams = [];
    
    if (status && status !== 'all') {
      whereClause += ' WHERE o.status = ?';
      queryParams.push(status);
    }
    
    if (search) {
      whereClause += whereClause ? ' AND' : ' WHERE';
      whereClause += ' (CONCAT(p.first_name, " ", p.last_name) LIKE ? OR o.email_id LIKE ? OR o.order_id LIKE ?)';
      queryParams.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    // Get total count for pagination
    const countQuery = `
      SELECT COUNT(*) as total
      FROM Orders o
      LEFT JOIN profiles p ON o.email_id = p.email_address
      ${whereClause}
    `;
    
    const [countResult] = await conn.execute(countQuery, queryParams);
    const totalOrders = countResult[0].total;
    const totalPages = Math.ceil(totalOrders / limit);

    // Main query with pagination
    const query = `
      SELECT 
        o.order_id AS id,
        CONCAT(p.first_name, ' ', p.last_name) AS customer,
        o.delivery_date AS date,
        o.status,
        o.email_id,
        p.address_line_1, p.address_line_2, p.city, p.state, p.postal_code, p.country,
        o.pid_1, o.pid_2, o.pid_3, o.pid_4, o.pid_5,
        o.pid_6, o.pid_7, o.pid_8, o.pid_9, o.pid_10
      FROM Orders o
      LEFT JOIN profiles p ON o.email_id = p.email_address
      ${whereClause}
      ORDER BY o.order_id DESC
      LIMIT ? OFFSET ?
    `;

    const [results] = await conn.execute(query, [...queryParams, limit, offset]);

    if (results.length === 0) {
      return res.json({
        status: "success",
        count: 0,
        orders: [],
        pagination: {
          page,
          limit,
          totalOrders,
          totalPages,
          hasNext: false,
          hasPrev: false
        },
        timestamp: new Date().toISOString(),
      });
    }

    // Collect all unique product IDs from all orders
    const allProductIds = [];
    results.forEach(order => {
      const productIds = [
        order.pid_1, order.pid_2, order.pid_3, order.pid_4, order.pid_5,
        order.pid_6, order.pid_7, order.pid_8, order.pid_9, order.pid_10,
      ].filter(pid => pid);
      
      productIds.forEach(pid => {
        const [itemId] = pid.split("-");
        if (!allProductIds.includes(itemId)) {
          allProductIds.push(itemId);
        }
      });
    });

    // Fetch all products in one query
    let productsMap = {};
    if (allProductIds.length > 0) {
      const placeholders = allProductIds.map(() => '?').join(',');
      const productsQuery = `
        SELECT PID, name, price, imglink AS image 
        FROM All_Items 
        WHERE PID IN (${placeholders})
      `;
      
      const [productResults] = await conn.execute(productsQuery, allProductIds);
      
      // Create a map for quick product lookup
      productResults.forEach(product => {
        productsMap[product.PID] = product;
      });
    }

    // Process orders with the fetched products
    const formatted = results.map(order => {
      const productIds = [
        order.pid_1, order.pid_2, order.pid_3, order.pid_4, order.pid_5,
        order.pid_6, order.pid_7, order.pid_8, order.pid_9, order.pid_10,
      ].filter(pid => pid);

      let total_amount = 0;
      let products = [];

      productIds.forEach(pid => {
        const [itemId, quantity] = pid.split("-");
        const product = productsMap[itemId];
        
        if (product) {
          const qty = parseInt(quantity) || 1;
          const price = parseFloat(product.price) || 0;
          total_amount += price * qty;

          // Determine source per product
          let source = "Unknown";
          if (itemId.startsWith("2")) source = "Electrical";
          else if (itemId.startsWith("1")) source = "Electronics";

          products.push({
            id: product.PID,
            name: product.name,
            image: product.image,
            price: price.toFixed(2),
            quantity: qty,
            subtotal: (price * qty).toFixed(2),
            source: source,
          });
        }
      });

      // Infer order source from first product
      const inferSource = () => {
        for (let pid of productIds) {
          if (pid.startsWith("2")) return "Electrical";
          if (pid.startsWith("1")) return "Electronics";
        }
        return "Unknown";
      };

      return {
        id: `ORD${String(order.id).padStart(3, "0")}`,
        customer: order.customer || "Unknown",
        date: order.date ? new Date(order.date).toISOString().split("T")[0] : "",
        amount: total_amount.toFixed(2),
        status: order.status || "Pending",
        source: inferSource(),
        email_id: order.email_id || "Unknown",
        shipping_address: {
          address_line1: order.address_line_1 || "",
          address_line2: order.address_line_2 || "",
          city: order.city || "",
          state: order.state || "",
          postal_code: order.postal_code || "",
          country: order.country || "",
        },
        products: products,
      };
    });

    res.json({
      status: "success",
      count: formatted.length,
      orders: formatted,
      pagination: {
        page,
        limit,
        totalOrders,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1
      },
      filters: {
        status: status || 'all',
        search: search || ''
      },
      timestamp: new Date().toISOString(),
    });

  } catch (err) {
    console.error(`[${new Date().toISOString()}] ❌ Error fetching orders:`, err);
    res.status(500).json({
      status: "error",
      message: "Failed to fetch orders",
      details: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error',
      timestamp: new Date().toISOString(),
    });
  } finally {
    if (conn) {
      try {
        conn.release(); // Return connection to pool
      } catch (releaseErr) {
        console.error("Error releasing connection:", releaseErr);
      }
    }
  }
});

// get single order
app.get("/customer/api/orders/:orderId", async (req, res) => {
  let conn;
  try {
    const { orderId } = req.params;

    // Convert "ORD038" -> 38 (numeric) or handle plain numeric IDs
    const numericOrderId = parseInt(orderId.replace(/^ORD/, ""), 10);
    
    if (isNaN(numericOrderId)) {
      return res.status(400).json({
        status: "error",
        message: "Invalid orderId format. Use ORDxxx or numeric ID",
        timestamp: new Date().toISOString()
      });
    }

    // Use connection pool instead of creating new connection
    conn = await pool.getConnection();

    // Fetch order + profile info
    const orderQuery = `
      SELECT 
        o.order_id AS id,
        CONCAT(COALESCE(p.first_name, ''), ' ', COALESCE(p.last_name, '')) AS customer,
        p.first_name,
        p.last_name,
        p.phone_number,
        o.delivery_date AS date,
        o.status,
        o.email_id,
        p.address_line_1, p.address_line_2, p.city, p.state, p.postal_code, p.country,
        o.pid_1, o.pid_2, o.pid_3, o.pid_4, o.pid_5,
        o.pid_6, o.pid_7, o.pid_8, o.pid_9, o.pid_10
      FROM Orders o
      LEFT JOIN profiles p ON o.email_id = p.email_address
      WHERE o.order_id = ?
      LIMIT 1
    `;

    const [orderResults] = await conn.execute(orderQuery, [numericOrderId]);

    if (orderResults.length === 0) {
      return res.status(404).json({
        status: "error",
        message: "Order not found",
        timestamp: new Date().toISOString()
      });
    }

    const order = orderResults[0];

    // Extract and validate product IDs
    const productIds = [
      order.pid_1, order.pid_2, order.pid_3, order.pid_4, order.pid_5,
      order.pid_6, order.pid_7, order.pid_8, order.pid_9, order.pid_10,
    ].filter(pid => pid && pid.toString().trim() !== "");

    if (productIds.length === 0) {
      return res.json({
        status: "success",
        order: {
          id: `ORD${String(order.id).padStart(3, "0")}`,
          customer: order.customer && order.customer.trim() !== " " ? order.customer.trim() : "Unknown",
          phone: order.phone_number || "",
          date: order.date ? new Date(order.date).toISOString().split("T")[0] : "",
          amount: "0.00",
          status: order.status || "Pending",
          email_id: order.email_id || "",
          customer_details: {
            first_name: order.first_name || "",
            last_name: order.last_name || "",
            phone: order.phone_number || "",
            email: order.email_id || ""
          },
          shipping_address: {
            address_line1: order.address_line_1 || "",
            address_line2: order.address_line_2 || "",
            city: order.city || "",
            state: order.state || "",
            postal_code: order.postal_code || "",
            country: order.country || "",
          },
          products: [],
          products_count: 0,
          order_summary: {
            subtotal: "0.00",
            tax: "0.00",
            shipping: "0.00",
            total: "0.00"
          }
        },
        timestamp: new Date().toISOString()
      });
    }

    // Extract unique item IDs for batch fetching
    const uniqueItemIds = [];
    
    productIds.forEach(pid => {
      const [itemId] = pid.toString().split("-");
      if (itemId && !uniqueItemIds.includes(itemId)) {
        uniqueItemIds.push(itemId);
      }
    });

    let productsMap = {};
    
    // Only fetch products if we have valid item IDs
    if (uniqueItemIds.length > 0) {
      // Batch fetch all products in one query (MAJOR OPTIMIZATION)
      const placeholders = uniqueItemIds.map(() => '?').join(',');
      const productsQuery = `
        SELECT PID, name, price, imglink AS image, category, description, subcat
        FROM All_Items 
        WHERE PID IN (${placeholders})
      `;

      const [productResults] = await conn.execute(productsQuery, uniqueItemIds);

      // Create product lookup map for O(1) access
      productResults.forEach(product => {
        productsMap[product.PID] = product;
      });
    }

    // Build products array with calculated totals
    let total_amount = 0;
    const products = [];

    productIds.forEach(pid => {
      const [itemId, quantity] = pid.toString().split("-");
      const product = productsMap[itemId];

      if (product) {
        const qty = parseInt(quantity) || 1;
        const price = parseFloat(product.price) || 0;
        const subtotal = price * qty;
        total_amount += subtotal;

        // Determine source based on PID prefix
        let source = "Unknown";
        if (itemId.startsWith("2")) source = "Electrical";
        else if (itemId.startsWith("1")) source = "Electronics";

        products.push({
          id: product.PID,
          name: product.name || "Unknown Product",
          image: product.image || "",
          price: price.toFixed(2),
          quantity: qty,
          subtotal: subtotal.toFixed(2),
          source: source,
          category: product.category || "",
          description: product.description || "",
          subcat: product.subcat || ""
        });
      } else {
        // Log missing products for debugging
        console.warn(`Product not found: ${itemId}`);
      }
    });

    // Build final order response
    const orderDetails = {
      id: `ORD${String(order.id).padStart(3, "0")}`,
      customer: order.customer && order.customer.trim() !== " " ? order.customer.trim() : "Unknown",
      phone: order.phone_number || "",
      date: order.date ? new Date(order.date).toISOString().split("T")[0] : "",
      amount: total_amount.toFixed(2),
      status: order.status || "Pending",
      email_id: order.email_id || "",
      customer_details: {
        first_name: order.first_name || "",
        last_name: order.last_name || "",
        phone: order.phone_number || "",
        email: order.email_id || ""
      },
      shipping_address: {
        address_line1: order.address_line_1 || "",
        address_line2: order.address_line_2 || "",
        city: order.city || "",
        state: order.state || "",
        postal_code: order.postal_code || "",
        country: order.country || "",
      },
      products: products,
      products_count: products.length,
      order_summary: {
        subtotal: total_amount.toFixed(2),
        tax: "0.00", // Add tax calculation if needed
        shipping: "0.00", // Add shipping calculation if needed
        total: total_amount.toFixed(2)
      }
    };

    res.json({
      status: "success",
      order: orderDetails,
      timestamp: new Date().toISOString()
    });

  } catch (err) {
    console.error(`[${new Date().toISOString()}] ❌ Customer order details error:`, err);
    
    // Different error responses based on error type
    if (err.code === 'ECONNREFUSED') {
      return res.status(503).json({
        status: "error",
        message: "Database connection failed",
        timestamp: new Date().toISOString()
      });
    }

    if (err.code === 'ER_NO_SUCH_TABLE') {
      return res.status(500).json({
        status: "error",
        message: "Database schema error",
        timestamp: new Date().toISOString()
      });
    }

    if (err.code === 'ER_BAD_FIELD_ERROR') {
      return res.status(500).json({
        status: "error",
        message: "Database column error - please contact support",
        timestamp: new Date().toISOString()
      });
    }

    res.status(500).json({
      status: "error",
      message: "Internal Server Error",
      details: process.env.NODE_ENV === 'development' ? err.message : "An unexpected error occurred",
      timestamp: new Date().toISOString(),
    });

  } finally {
    // Always release connection back to pool
    if (conn) {
      try {
        conn.release();
      } catch (releaseErr) {
        console.error("Error releasing connection:", releaseErr);
      }
    }
  }
});

// get order by user email

app.get("/customer/api/orders/email/:emailId", async (req, res) => {
  let conn;
  try {
    const { emailId } = req.params;

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(emailId)) {
      return res.status(400).json({
        status: "error",
        message: "Invalid email format",
        timestamp: new Date().toISOString()
      });
    }

    // Use connection pool
    conn = await pool.getConnection();

    // Fetch all orders for the email with profile info (optimized with single query)
    const ordersQuery = `
      SELECT 
        o.order_id AS id,
        CONCAT(COALESCE(p.first_name, ''), ' ', COALESCE(p.last_name, '')) AS customer,
        p.first_name,
        p.last_name,
        p.phone_number,
        o.delivery_date AS date,
        o.status,
        o.email_id,
        p.address_line_1, p.address_line_2, p.city, p.state, p.postal_code, p.country,
        o.pid_1, o.pid_2, o.pid_3, o.pid_4, o.pid_5,
        o.pid_6, o.pid_7, o.pid_8, o.pid_9, o.pid_10
      FROM Orders o
      LEFT JOIN profiles p ON o.email_id = p.email_address
      WHERE o.email_id = ?
      ORDER BY o.order_id DESC
    `;

    const [orderResults] = await conn.execute(ordersQuery, [emailId]);

    if (orderResults.length === 0) {
      return res.status(404).json({
        status: "error",
        message: "No orders found for this email",
        timestamp: new Date().toISOString()
      });
    }

    // Extract ALL unique product IDs from ALL orders for batch fetching
    const allProductIds = new Set();
    
    orderResults.forEach(order => {
      const productIds = [
        order.pid_1, order.pid_2, order.pid_3, order.pid_4, order.pid_5,
        order.pid_6, order.pid_7, order.pid_8, order.pid_9, order.pid_10,
      ].filter(pid => pid && pid.toString().trim() !== "");

      productIds.forEach(pid => {
        const [itemId] = pid.toString().split("-");
        if (itemId) {
          allProductIds.add(itemId);
        }
      });
    });

    // Batch fetch ALL products in ONE query (MAJOR PERFORMANCE BOOST)
    let productsMap = {};
    
    if (allProductIds.size > 0) {
      const uniqueItemIds = Array.from(allProductIds);
      const placeholders = uniqueItemIds.map(() => '?').join(',');
      const productsQuery = `
        SELECT PID, name, price, imglink AS image, category, description, subcat
        FROM All_Items 
        WHERE PID IN (${placeholders})
      `;

      const [productResults] = await conn.execute(productsQuery, uniqueItemIds);

      // Create product lookup map for O(1) access
      productResults.forEach(product => {
        productsMap[product.PID] = product;
      });
    }

    // Process each order
    const processedOrders = orderResults.map(order => {
      // Extract product IDs for this order
      const productIds = [
        order.pid_1, order.pid_2, order.pid_3, order.pid_4, order.pid_5,
        order.pid_6, order.pid_7, order.pid_8, order.pid_9, order.pid_10,
      ].filter(pid => pid && pid.toString().trim() !== "");

      let total_amount = 0;
      const products = [];

      // Process products for this order
      productIds.forEach(pid => {
        const [itemId, quantity] = pid.toString().split("-");
        const product = productsMap[itemId];

        if (product) {
          const qty = parseInt(quantity) || 1;
          const price = parseFloat(product.price) || 0;
          const subtotal = price * qty;
          total_amount += subtotal;

          // Determine source based on PID prefix
          let source = "Unknown";
          if (itemId.startsWith("2")) source = "Electrical";
          else if (itemId.startsWith("1")) source = "Electronics";

          products.push({
            id: product.PID,
            name: product.name || "Unknown Product",
            image: product.image || "",
            price: price.toFixed(2),
            quantity: qty,
            subtotal: subtotal.toFixed(2),
            source: source,
            category: product.category || "",
            description: product.description || "",
            subcat: product.subcat || ""
          });
        }
      });

      // Return processed order
      return {
        id: `ORD${String(order.id).padStart(3, "0")}`,
        customer: order.customer && order.customer.trim() !== " " ? order.customer.trim() : "Unknown",
        phone: order.phone_number || "",
        date: order.date ? new Date(order.date).toISOString().split("T")[0] : "",
        amount: total_amount.toFixed(2),
        status: order.status || "Pending",
        email_id: order.email_id || "",
        customer_details: {
          first_name: order.first_name || "",
          last_name: order.last_name || "",
          phone: order.phone_number || "",
          email: order.email_id || ""
        },
        shipping_address: {
          address_line1: order.address_line_1 || "",
          address_line2: order.address_line_2 || "",
          city: order.city || "",
          state: order.state || "",
          postal_code: order.postal_code || "",
          country: order.country || "",
        },
        products: products,
        products_count: products.length,
        order_summary: {
          subtotal: total_amount.toFixed(2),
          tax: "0.00",
          shipping: "0.00",
          total: total_amount.toFixed(2)
        }
      };
    });

    // Calculate summary statistics
    const totalOrders = processedOrders.length;
    const totalAmount = processedOrders.reduce((sum, order) => sum + parseFloat(order.amount), 0);
    const totalProducts = processedOrders.reduce((sum, order) => sum + order.products_count, 0);

    // Group orders by status for quick overview
    const ordersByStatus = processedOrders.reduce((acc, order) => {
      const status = order.status.toLowerCase();
      acc[status] = (acc[status] || 0) + 1;
      return acc;
    }, {});

    res.json({
      status: "success",
      email: emailId,
      orders: processedOrders,
      summary: {
        total_orders: totalOrders,
        total_amount: totalAmount.toFixed(2),
        total_products: totalProducts,
        orders_by_status: ordersByStatus
      },
      timestamp: new Date().toISOString()
    });

  } catch (err) {
    console.error(`[${new Date().toISOString()}] ❌ Customer orders by email error:`, err);
    
    // Different error responses based on error type
    if (err.code === 'ECONNREFUSED') {
      return res.status(503).json({
        status: "error",
        message: "Database connection failed",
        timestamp: new Date().toISOString()
      });
    }

    if (err.code === 'ER_NO_SUCH_TABLE') {
      return res.status(500).json({
        status: "error",
        message: "Database schema error",
        timestamp: new Date().toISOString()
      });
    }

    if (err.code === 'ER_BAD_FIELD_ERROR') {
      return res.status(500).json({
        status: "error",
        message: "Database column error - please contact support",
        timestamp: new Date().toISOString()
      });
    }

    res.status(500).json({
      status: "error",
      message: "Internal Server Error",
      details: process.env.NODE_ENV === 'development' ? err.message : "An unexpected error occurred",
      timestamp: new Date().toISOString(),
    });

  } finally {
    // Always release connection back to pool
    if (conn) {
      try {
        conn.release();
      } catch (releaseErr) {
        console.error("Error releasing connection:", releaseErr);
      }
    }
  }
});

// Add pagination support for users with many orders
// app.get("/customer/api/orders/email/:emailId/paginated", async (req, res) => {
//   let conn;
//   try {
//     const { emailId } = req.params;
//     const page = parseInt(req.query.page) || 1;
//     const limit = parseInt(req.query.limit) || 10;
//     const offset = (page - 1) * limit;

//     // Basic email validation
//     const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
//     if (!emailRegex.test(emailId)) {
//       return res.status(400).json({
//         status: "error",
//         message: "Invalid email format",
//         timestamp: new Date().toISOString()
//       });
//     }

//     conn = await pool.getConnection();

//     // Get total count for pagination
//     const countQuery = `SELECT COUNT(*) as total FROM Orders WHERE email_id = ?`;
//     const [countResult] = await conn.execute(countQuery, [emailId]);
//     const totalOrders = countResult[0].total;

//     // Fetch paginated orders
//     const ordersQuery = `
//       SELECT 
//         o.order_id AS id,
//         CONCAT(COALESCE(p.first_name, ''), ' ', COALESCE(p.last_name, '')) AS customer,
//         p.first_name,
//         p.last_name,
//         p.phone_number,
//         o.delivery_date AS date,
//         o.status,
//         o.email_id,
//         p.address_line_1, p.address_line_2, p.city, p.state, p.postal_code, p.country,
//         o.pid_1, o.pid_2, o.pid_3, o.pid_4, o.pid_5,
//         o.pid_6, o.pid_7, o.pid_8, o.pid_9, o.pid_10,
//         o.created_at
//       FROM Orders o
//       LEFT JOIN profiles p ON o.email_id = p.email_address
//       WHERE o.email_id = ?
//       ORDER BY o.created_at DESC, o.order_id DESC
//       LIMIT ? OFFSET ?
//     `;

//     const [orderResults] = await conn.execute(ordersQuery, [emailId, limit, offset]);

//     if (orderResults.length === 0 && page === 1) {
//       return res.status(404).json({
//         status: "error",
//         message: "No orders found for this email",
//         timestamp: new Date().toISOString()
//       });
//     }

//     // Process orders (same logic as above but for paginated results)
//     const allProductIds = new Set();
    
//     orderResults.forEach(order => {
//       const productIds = [
//         order.pid_1, order.pid_2, order.pid_3, order.pid_4, order.pid_5,
//         order.pid_6, order.pid_7, order.pid_8, order.pid_9, order.pid_10,
//       ].filter(pid => pid && pid.toString().trim() !== "");

//       productIds.forEach(pid => {
//         const [itemId] = pid.toString().split("-");
//         if (itemId) allProductIds.add(itemId);
//       });
//     });

//     let productsMap = {};
    
//     if (allProductIds.size > 0) {
//       const uniqueItemIds = Array.from(allProductIds);
//       const placeholders = uniqueItemIds.map(() => '?').join(',');
//       const productsQuery = `
//         SELECT PID, name, price, imglink AS image, category, description, subcat
//         FROM All_Items 
//         WHERE PID IN (${placeholders})
//       `;

//       const [productResults] = await conn.execute(productsQuery, uniqueItemIds);
//       productResults.forEach(product => {
//         productsMap[product.PID] = product;
//       });
//     }

//     const processedOrders = orderResults.map(order => {
//       const productIds = [
//         order.pid_1, order.pid_2, order.pid_3, order.pid_4, order.pid_5,
//         order.pid_6, order.pid_7, order.pid_8, order.pid_9, order.pid_10,
//       ].filter(pid => pid && pid.toString().trim() !== "");

//       let total_amount = 0;
//       const products = [];

//       productIds.forEach(pid => {
//         const [itemId, quantity] = pid.toString().split("-");
//         const product = productsMap[itemId];

//         if (product) {
//           const qty = parseInt(quantity) || 1;
//           const price = parseFloat(product.price) || 0;
//           const subtotal = price * qty;
//           total_amount += subtotal;

//           let source = "Unknown";
//           if (itemId.startsWith("2")) source = "Electrical";
//           else if (itemId.startsWith("1")) source = "Electronics";

//           products.push({
//             id: product.PID,
//             name: product.name || "Unknown Product",
//             image: product.image || "",
//             price: price.toFixed(2),
//             quantity: qty,
//             subtotal: subtotal.toFixed(2),
//             source: source,
//             category: product.category || "",
//             description: product.description || "",
//             subcat: product.subcat || ""
//           });
//         }
//       });

//       return {
//         id: `ORD${String(order.id).padStart(3, "0")}`,
//         customer: order.customer && order.customer.trim() !== " " ? order.customer.trim() : "Unknown",
//         phone: order.phone_number || "",
//         date: order.date ? new Date(order.date).toISOString().split("T")[0] : "",
//         created_at: order.created_at ? new Date(order.created_at).toISOString() : "",
//         amount: total_amount.toFixed(2),
//         status: order.status || "Pending",
//         email_id: order.email_id || "",
//         customer_details: {
//           first_name: order.first_name || "",
//           last_name: order.last_name || "",
//           phone: order.phone_number || "",
//           email: order.email_id || ""
//         },
//         shipping_address: {
//           address_line1: order.address_line_1 || "",
//           address_line2: order.address_line_2 || "",
//           city: order.city || "",
//           state: order.state || "",
//           postal_code: order.postal_code || "",
//           country: order.country || "",
//         },
//         products: products,
//         products_count: products.length,
//         order_summary: {
//           subtotal: total_amount.toFixed(2),
//           tax: "0.00",
//           shipping: "0.00",
//           total: total_amount.toFixed(2)
//         }
//       };
//     });

//     const totalPages = Math.ceil(totalOrders / limit);

//     res.json({
//       status: "success",
//       email: emailId,
//       orders: processedOrders,
//       pagination: {
//         current_page: page,
//         total_pages: totalPages,
//         total_orders: totalOrders,
//         per_page: limit,
//         has_next: page < totalPages,
//         has_prev: page > 1
//       },
//       timestamp: new Date().toISOString()
//     });

//   } catch (err) {
//     console.error(`[${new Date().toISOString()}] ❌ Paginated orders error:`, err);
    
//     res.status(500).json({
//       status: "error",
//       message: "Internal Server Error",
//       details: process.env.NODE_ENV === 'development' ? err.message : "An unexpected error occurred",
//       timestamp: new Date().toISOString(),
//     });

//   } finally {
//     if (conn) {
//       try {
//         conn.release();
//       } catch (releaseErr) {
//         console.error("Error releasing connection:", releaseErr);
//       }
//     }
//   }
// });


// query

// get query

app.get("/admin/enquiries", async (req, res) => {
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
    const processedRows = rows.map(row => {
      let type = '';
      let details = row.rawDetails || '';
      
      // Check if details contains "Solar Type: " pattern
      const typeMatch = details.match(/Solar Type:\s*([^\n]*)/i);
      if (typeMatch) {
        type = typeMatch[1].trim();
        // Remove the solar type line from details
        details = details.replace(/Solar Type:\s*[^\n]*\n?/i, '').trim();
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
        status: row.status
      };
    });
    
    res.json(processedRows);
  } catch (err) {
    res.status(500).json({ success: false, message: "Error fetching enquiries", error: err.message });
  }
});

// post query
app.post("/api/enquiries", async (req, res) => {
  try {
    const { firstName, lastName, email, phone, service, type, details, formname } = req.body;

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
        message: "You already have a pending enquiry. Please wait for it to be completed before submitting a new one.",
        existingEnquiry: {
          id: existingEnquiries[0].request_id,
          status: existingEnquiries[0].status
        }
      });
    }

    // Format the message more cleanly
    let message = details || '';
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
      message: "Enquiry submitted successfully" 
    });

  } catch (err) {
    res.status(500).json({ 
      success: false, 
      message: "Error saving enquiry", 
      error: err.message 
    });
  }
});


// Admin: Update enquiry status
app.put("/admin/enquiries/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    // Check if status is provided
    if (!status) {
      return res.status(400).json({ success: false, message: "Status is required" });
    }

    const validStatuses = ["Pending", "In Progress", "Completed"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ 
        success: false, 
        message: `Invalid status. Valid statuses are: ${validStatuses.join(", ")}`,
        receivedStatus: status
      });
    }

    const conn = await mysql2Promise.createConnection(banerjeeConfig);
    
    // Using 'request_id' as the actual database column name
    const [result] = await conn.execute(
      "UPDATE ConsultationRequests SET status = ? WHERE request_id = ?",
      [status, id]
    );

    // Close the connection
    await conn.end();

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Enquiry not found" });
    }

    res.json({ success: true, message: "Status updated successfully" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error updating status", error: err.message });
  }
});



// Shop Admin Item Upload Routes (Banerjee DB)

app.post("/api/upload-items", async (req, res) => {
  const { type, items } = req.body;

  // Validate inputs
  if (!type || !items || !Array.isArray(items)) {
    return res
      .status(400)
      .json({ success: false, message: "Missing type or items array." });
  }

  // Check if items array is too large - increased limit for your needs
  if (items.length > 10000) {
    return res
      .status(400)
      .json({ success: false, message: "Too many items. Maximum 10000 items per upload." });
  }

  // Decide target table and prefix
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
    // Create connection with optimized settings
    conn = await mysql2Promise.createConnection({
      ...banerjeeConfig,
      acquireTimeout: 300000, // 5 minutes
      timeout: 300000, // 5 minutes
      reconnect: true,
      // Optimize for bulk operations
      multipleStatements: true
    });

    // Start transaction for data consistency
    await conn.beginTransaction();

    // Clear old data
    await conn.execute(`DELETE FROM ${targetTable}`);
    await conn.execute(`DELETE FROM All_Items WHERE PID LIKE '${prefix}%'`);

    // Get the next starting PID
    let currentPID = await getNextPID(conn, targetTable, prefix);

    // Prepare batch insert data
    const batchSize = 100; // Process in batches of 100
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
        item.subcat || ""
      ];
      
      targetTableValues.push(itemData);
      allItemsValues.push(itemData);

      // Execute batch when we reach batch size or at the end
      if (targetTableValues.length === batchSize || i === items.length - 1) {
        // Batch insert into target table
        if (targetTableValues.length > 0) {
          const targetPlaceholders = targetTableValues.map(() => "(?, ?, ?, ?, ?, ?, ?)").join(", ");
          const targetFlatValues = targetTableValues.flat();
          
          await conn.execute(
            `INSERT INTO ${targetTable} (PID, name, category, price, imglink, description, subcat) VALUES ${targetPlaceholders}`,
            targetFlatValues
          );

          // Batch insert into All_Items
          const allItemsPlaceholders = allItemsValues.map(() => "(?, ?, ?, ?, ?, ?, ?)").join(", ");
          const allItemsFlatValues = allItemsValues.flat();
          
          await conn.execute(
            `INSERT INTO All_Items (PID, name, category, price, imglink, description, subcat) VALUES ${allItemsPlaceholders}`,
            allItemsFlatValues
          );

          // Clear arrays for next batch
          targetTableValues.length = 0;
          allItemsValues.length = 0;
        }
      }
    }

    // Commit transaction
    await conn.commit();

    res.json({
      success: true,
      message: `Successfully processed ${items.length} items. Wiped ${targetTable}, inserted ${items.length} items, also copied to All_Items.`,
      itemsProcessed: items.length
    });

  } catch (err) {
    console.error("Error processing upload:", err);
    
    // Rollback transaction if it was started
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
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  } finally {
    // Always close the connection
    if (conn) {
      try {
        await conn.end();
      } catch (closeErr) {
        console.error("Error closing connection:", closeErr);
      }
    }
  }
});

// Helper function to get next PID - optimized version
async function getNextPID(conn, tableName, prefix) {
  try {
    const [rows] = await conn.execute(
      `SELECT MAX(CAST(SUBSTRING(PID, 2) AS UNSIGNED)) as maxId FROM ${tableName} WHERE PID LIKE ?`,
      [`${prefix}%`]
    );
    
    const maxId = rows[0]?.maxId || 0;
    return `${prefix}${String(maxId + 1).padStart(6, '0')}`;
  } catch (err) {
    console.error("Error getting next PID:", err);
    // Fallback to timestamp-based ID
    return `${prefix}${Date.now()}`;
  }
}

// Course Management Routes (BECS DB)
app.get("/api/courses", async (req, res, next) => {
  try {
    const [results] = await becsPool.query(`
            SELECT course_id, course_name, course_description, price, image_link FROM courses
        `);
    res.json({
      status: "success",
      count: results.length,
      courses: results,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("❌ Error fetching courses:", err);
    if (err.code === "PROTOCOL_SEQUENCE_TIMEOUT") {
      res.status(504).json({
        status: "error",
        message: "Database query timed out",
        error: err.message,
        timestamp: new Date().toISOString(),
      });
    } else if (
      err.code === "ETIMEDOUT" ||
      err.code === "PROTOCOL_CONNECTION_LOST"
    ) {
      res.status(503).json({
        status: "error",
        message: "Database connection timed out",
        error: err.message,
        timestamp: new Date().toISOString(),
      });
    } else {
      next(err);
    }
  }
});

app.get(
  "/api/user/:uid/courses",
  authenticateFirebaseToken,
  async (req, res, next) => {
    const { uid } = req.params;

    if (!req.user || uid !== req.user.uid) {
      return res.status(403).json({
        error: "Forbidden",
        message: "You can only access your own courses",
        timestamp: new Date().toISOString(),
      });
    }

    const maxRetries = 3;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const [results] = await becsPool.query(
          `
                SELECT c.course_id, c.course_name, c.course_description, c.price, c.image_link, pc.purchased_at
                FROM purchased_courses pc
                JOIN courses c ON pc.course_id = c.course_id
                WHERE pc.firebase_uid = ?
            `,
          [uid]
        );

        return res.json({
          status: "success",
          count: results.length,
          courses: results,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        if (
          ["ECONNRESET", "ETIMEDOUT"].includes(err.code) &&
          attempt < maxRetries
        ) {
          await new Promise((r) => setTimeout(r, 1000 * attempt));
          continue;
        }
        return next(err);
      }
    }
  }
);

// app.post('/api/create-order', async (req, res) => {
//     const { key, amount, currency, name, description, image } = req.body;

//     // Validate required fields
//     if (!amount || !currency || !name || !description || !image) {
//         console.warn(`[${new Date().toISOString()}] ❌ Missing required fields in /create-order`);
//         return res.status(400).json({
//             status: 'error',
//             message: 'amount, currency, name, description, and image are required',
//             timestamp: new Date().toISOString()
//         });
//     }

//     if (isNaN(amount) || amount <= 0) {
//         console.warn(`[${new Date().toISOString()}] ❌ Invalid amount: ${amount}`);
//         return res.status(400).json({
//             status: 'error',
//             message: 'Amount must be a positive number',
//             timestamp: new Date().toISOString()
//         });
//     }

//     if (currency !== 'INR') {
//         console.warn(`[${new Date().toISOString()}] ❌ Unsupported currency: ${currency}`);
//         return res.status(400).json({
//             status: 'error',
//             message: 'Only INR currency is supported',
//             timestamp: new Date().toISOString()
//         });
//     }

//     try {
//         const order = await razorpay.orders.create({
//             amount: Math.round(amount),
//             currency: 'INR',
//             receipt: `receipt_${Date.now()}`,
//             payment_capture: 1
//         });

//         return res.json({
//             status: 'success',
//             orderId: order.id,
//             amount: order.amount,
//             currency: order.currency,
//             name,
//             description,
//             image,
//             timestamp: new Date().toISOString()
//         });

//     } catch (err) {
//         console.error(`[${new Date().toISOString()}] ❌ Error creating Razorpay order:`, err);
//         return res.status(500).json({
//             status: 'error',
//             message: 'Failed to create order',
//             details: err.message,
//             timestamp: new Date().toISOString()
//         });
//     }
// });

// app.post('/verify-payment', (req, res) => {
//     try {
//         const { razorpay_payment_id, razorpay_order_id, razorpay_signature } = req.body;
//         if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature) {
//             console.warn(`[${new Date().toISOString()}] ❌ Missing payment details in /verify-payment request`);
//             return res.status(400).json({
//                 status: 'error',
//                 message: 'razorpay_payment_id, razorpay_order_id, and razorpay_signature are required',
//                 timestamp: new Date().toISOString()
//             });
//         }
//         const payload = `${razorpay_order_id}|${razorpay_payment_id}`;
//         const expectedSignature = crypto
//             .createHmac('sha256', RAZORPAY_KEY_SECRET)
//             .update(payload)
//             .digest('hex');
//         if (expectedSignature === razorpay_signature) {
//             return res.json({
//                 status: 'success',
//                 verified: true,
//                 message: 'Payment verified successfully',
//                 timestamp: new Date().toISOString()
//             });
//         } else {
//             console.warn(`[${new Date().toISOString()}] ❌ Payment verification failed: Invalid signature`);
//             return res.status(400).json({
//                 status: 'error',
//                 verified: false,
//                 message: 'Invalid payment signature',
//                 timestamp: new Date().toISOString()
//             });
//         }
//     } catch (error) {
//         console.error(`[${new Date().toISOString()}] ❌ Verification error:`, error.message);
//         return res.status(500).json({
//             status: 'error',
//             message: `Server error: ${error.message}`,
//             timestamp: new Date().toISOString()
//         });
//     }
// });
// Route to verify and complete purchase

app.post("/api/user/:uid/purchase-course", async (req, res, next) => {
  const { uid } = req.params;
  const {
    course_id,
    razorpay_payment_id,
    razorpay_order_id,
    razorpay_signature,
  } = req.body;

  if (!req.user || uid !== req.user.uid) {
    return res.status(403).json({
      error: "Forbidden",
      message: "You can only purchase courses for your own account",
      timestamp: new Date().toISOString(),
    });
  }

  if (
    !course_id ||
    !razorpay_payment_id ||
    !razorpay_order_id ||
    !razorpay_signature
  ) {
    return res.status(400).json({
      error: "Bad Request",
      message: "All payment fields are required",
      timestamp: new Date().toISOString(),
    });
  }

  try {
    const generatedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest("hex");

    if (generatedSignature !== razorpay_signature) {
      return res.status(400).json({
        status: "error",
        message: "Invalid payment signature",
        timestamp: new Date().toISOString(),
      });
    }

    const [courseResults] = await becsPool.query(
      `SELECT course_id, price FROM courses WHERE course_id = ?`,
      [course_id]
    );
    if (!courseResults.length) {
      return res.status(404).json({
        error: "Not Found",
        message: "Course not found",
        timestamp: new Date().toISOString(),
      });
    }

    const [existingPurchase] = await becsPool.query(
      `SELECT course_id FROM purchased_courses WHERE firebase_uid = ? AND course_id = ?`,
      [uid, course_id]
    );
    if (existingPurchase.length) {
      return res.status(400).json({
        error: "Bad Request",
        message: "Course already purchased",
        timestamp: new Date().toISOString(),
      });
    }

    await becsPool.query(
      `INSERT INTO purchased_courses (firebase_uid, course_id, purchased_at) VALUES (?, ?, NOW())`,
      [uid, course_id]
    );

    return res.json({
      status: "success",
      message: "Course purchased successfully",
      course_id,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    if (err.code === "ER_NO_REFERENCED_ROW_2") {
      return res.status(400).json({
        status: "error",
        message: "Invalid course ID",
        timestamp: new Date().toISOString(),
      });
    }
    next(err);
  }
});

app.get("/api/courses/:courseId/lectures", async (req, res, next) => {
  const { courseId } = req.params;
  const uid = req.user?.uid;

  const numericCourseId = parseInt(courseId, 10);
  if (!uid) {
    return res
      .status(401)
      .json({
        status: "error",
        message: "Unauthorized",
        timestamp: new Date().toISOString(),
      });
  }

  if (isNaN(numericCourseId) || numericCourseId <= 0) {
    return res
      .status(400)
      .json({
        status: "error",
        message: "Invalid course ID. Must be a positive integer.",
        timestamp: new Date().toISOString(),
      });
  }

  const maxRetries = 3;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const [courseExists] = await becsPool.query(
        "SELECT course_id, course_name FROM courses WHERE course_id = ?",
        [numericCourseId]
      );

      if (!courseExists.length) {
        return res
          .status(404)
          .json({
            status: "error",
            message: `Course with ID ${numericCourseId} not found`,
            timestamp: new Date().toISOString(),
          });
      }

      const [purchaseExists] = await becsPool.query(
        "SELECT course_id FROM purchased_courses WHERE firebase_uid = ? AND course_id = ?",
        [uid, numericCourseId]
      );

      if (!purchaseExists.length) {
        return res
          .status(403)
          .json({
            status: "error",
            message: "You have not purchased this course",
            timestamp: new Date().toISOString(),
          });
      }

      const [results] = await becsPool.query(
        `
                SELECT lecture_id, course_id, video_name, video_link, duration_minutes
                FROM lectures
                WHERE course_id = ?
                ORDER BY lecture_id ASC
            `,
        [numericCourseId]
      );

      return res.json({
        status: "success",
        count: results.length,
        lectures: results,
        course_name: courseExists[0].course_name,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      if (
        ["ECONNRESET", "ETIMEDOUT", "PROTOCOL_CONNECTION_LOST"].includes(
          err.code
        ) &&
        attempt < maxRetries
      ) {
        await new Promise((r) => setTimeout(r, 1000 * attempt));
        continue;
      }

      return res.status(503).json({
        status: "error",
        message: "Database error occurred",
        error: err.message,
        timestamp: new Date().toISOString(),
      });
    }
  }
});

// Teacher Panel Endpoints (BECS DB)
app.post("/api/teacher/login", async (req, res, next) => {
  const { teacher_id: teacherIdRaw, password } = req.body;
  const teacherId = parseInt(teacherIdRaw);
  if (isNaN(teacherId) || teacherId <= 0) {
    console.warn(`❌ Invalid teacher_id: ${teacherIdRaw}`);
    return res.status(400).json({
      status: "error",
      message: "Teacher ID must be a positive integer",
      timestamp: new Date().toISOString(),
    });
  }
  if (!password) {
    console.warn("❌ Missing password");
    return res.status(400).json({
      status: "error",
      message: "Password is required",
      timestamp: new Date().toISOString(),
    });
  }
  try {
    const [results] = await becsPool.query(
      `SELECT teacher_id, password
            FROM teachers
            WHERE teacher_id = ?`,
      [teacherId]
    );
    if (results.length === 0) {
      console.warn(`❌ No teacher found with teacher_id: ${teacherId}`);
      return res.status(401).json({
        status: "error",
        message: "Invalid teacher ID or password",
        timestamp: new Date().toISOString(),
      });
    }
    if (password !== results[0].password) {
      console.warn(`❌ Invalid password for teacher_id: ${teacherId}`);
      return res.status(401).json({
        status: "error",
        message: "Invalid teacher ID or password",
        timestamp: new Date().toISOString(),
      });
    }
    res.json({
      status: "success",
      message: "Login successful",
      teacher_id: teacherId,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("❌ Error during teacher login:", err);
    next(err);
  }
});

app.get(
  "/api/teacher/:teacher_id/profile",
  authenticateTeacher,
  async (req, res, next) => {
    const { teacher_id } = req.params;
    try {
      const [results] = await becsPool.query(
        `SELECT teacher_id, teacher_name, bio, subject
            FROM teachers
            WHERE teacher_id = ?`,
        [teacher_id]
      );
      if (results.length === 0) {
        console.warn(`❌ No teacher found with teacher_id: ${teacher_id}`);
        return res.status(404).json({
          status: "error",
          message: "Teacher not found",
          timestamp: new Date().toISOString(),
        });
      }
      res.json({
        status: "success",
        teacher: {
          teacher_id: results[0].teacher_id,
          name: results[0].teacher_name,
          bio: results[0].bio || "",
          expertise: results[0].subject || "",
        },
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error("❌ Error fetching teacher profile:", err);
      next(err);
    }
  }
);

app.post(
  "/api/teacher/:teacher_id/lectures",
  authenticateTeacher,
  async (req, res, next) => {
    const { teacher_id } = req.params;
    const { course_id, video_name, video_link, duration_minutes } = req.body;
    if (!course_id || !video_name || !video_link || !duration_minutes) {
      return res.status(400).json({
        status: "error",
        message: "Course ID, video name, video link, and duration are required",
        timestamp: new Date().toISOString(),
      });
    }
    if (
      !video_link.startsWith("https://www.youtube.com/") &&
      !video_link.startsWith("https://youtu.be/")
    ) {
      return res.status(400).json({
        status: "error",
        message: "Video link must be a valid YouTube URL",
        timestamp: new Date().toISOString(),
      });
    }
    try {
      const [result] = await becsPool.query(
        `INSERT INTO lectures (course_id, video_name, video_link, duration_minutes)
            SELECT ?, ?, ?, ?
            FROM teachers t
            WHERE t.teacher_id = ? AND t.course_id = ?`,
        [
          course_id,
          video_name,
          video_link,
          duration_minutes,
          teacher_id,
          course_id,
        ]
      );
      if (result.affectedRows === 0) {
        return res.status(403).json({
          status: "error",
          message: "You are not authorized to add lectures to this course",
          timestamp: new Date().toISOString(),
        });
      }
      res.json({
        status: "success",
        message: "Lecture added successfully",
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error("❌ Error adding lecture:", err);
      if (err.code === "ER_NO_REFERENCED_ROW_2") {
        return res.status(400).json({
          status: "error",
          message: "Invalid course ID",
          timestamp: new Date().toISOString(),
        });
      }
      next(err);
    }
  }
);

app.put(
  "/api/teacher/:teacher_id/lectures/:lecture_id",
  authenticateTeacher,
  async (req, res, next) => {
    const { teacher_id, lecture_id } = req.params;
    const { video_name, video_link, duration_minutes } = req.body;
    if (!video_name || !video_link || !duration_minutes) {
      return res.status(400).json({
        status: "error",
        message: "Video name, video link, and duration are required",
        timestamp: new Date().toISOString(),
      });
    }
    if (
      !video_link.startsWith("https://www.youtube.com/") &&
      !video_link.startsWith("https://youtu.be/")
    ) {
      return res.status(400).json({
        status: "error",
        message: "Video link must be a valid YouTube URL",
        timestamp: new Date().toISOString(),
      });
    }
    try {
      const [result] = await becsPool.query(
        `UPDATE lectures l
            JOIN courses c ON l.course_id = c.course_id
            JOIN teachers t ON t.course_id = c.course_id
            SET l.video_name = ?, l.video_link = ?, l.duration_minutes = ?
            WHERE l.lecture_id = ? AND t.teacher_id = ?`,
        [video_name, video_link, duration_minutes, lecture_id, teacher_id]
      );
      if (result.affectedRows === 0) {
        return res.status(404).json({
          status: "error",
          message: "Lecture not found or you are not authorized to edit it",
          timestamp: new Date().toISOString(),
        });
      }
      res.json({
        status: "success",
        message: "Lecture updated successfully",
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error("❌ Error updating lecture:", err);
      next(err);
    }
  }
);

app.delete(
  "/api/teacher/:teacher_id/lectures/:lecture_id",
  authenticateTeacher,
  async (req, res, next) => {
    const { teacher_id, lecture_id } = req.params;
    try {
      const [result] = await becsPool.query(
        `DELETE l FROM lectures l
            JOIN courses c ON l.course_id = c.course_id
            JOIN teachers t ON t.course_id = c.course_id
            WHERE l.lecture_id = ? AND t.teacher_id = ?`,
        [lecture_id, teacher_id]
      );
      if (result.affectedRows === 0) {
        return res.status(404).json({
          status: "error",
          message: "Lecture not found or you are not authorized to delete it",
          timestamp: new Date().toISOString(),
        });
      }
      res.json({
        status: "success",
        message: "Lecture deleted successfully",
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error("❌ Error deleting lecture:", err);
      next(err);
    }
  }
);

app.get(
  "/api/teacher/:teacher_id/lectures",
  authenticateTeacher,
  async (req, res, next) => {
    const { teacher_id } = req.params;
    try {
      const [results] = await becsPool.query(
        `SELECT l.lecture_id, l.course_id, l.video_name, l.video_link, l.duration_minutes, c.course_name
            FROM lectures l
            JOIN courses c ON l.course_id = c.course_id
            JOIN teachers t ON t.course_id = c.course_id
            WHERE t.teacher_id = ?`,
        [teacher_id]
      );
      res.json({
        status: "success",
        count: results.length,
        lectures: results,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error("❌ Error fetching lectures:", err);
      next(err);
    }
  }
);

app.put(
  "/api/teacher/:teacher_id/bio",
  authenticateTeacher,
  async (req, res, next) => {
    const { teacher_id } = req.params;
    const { bio } = req.body;
    try {
      const [result] = await becsPool.query(
        `UPDATE teachers
            SET bio = ?
            WHERE teacher_id = ?`,
        [bio, teacher_id]
      );
      if (result.affectedRows === 0) {
        return res.status(404).json({
          status: "error",
          message: "Teacher not found",
          timestamp: new Date().toISOString(),
        });
      }
      res.json({
        status: "success",
        message: "Bio updated successfully",
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error("❌ Error updating bio:", err);
      next(err);
    }
  }
);

app.put(
  "/api/teacher/:teacher_id/name",
  authenticateTeacher,
  async (req, res, next) => {
    const { teacher_id } = req.params;
    const { teacher_name } = req.body;
    if (!teacher_name) {
      return res.status(400).json({
        status: "error",
        message: "Teacher name is required",
        timestamp: new Date().toISOString(),
      });
    }
    try {
      const [result] = await becsPool.query(
        `UPDATE teachers SET teacher_name = ? WHERE teacher_id = ?`,
        [teacher_name, teacher_id]
      );
      if (result.affectedRows === 0) {
        return res.status(404).json({
          status: "error",
          message: "Teacher not found",
          timestamp: new Date().toISOString(),
        });
      }
      res.json({
        status: "success",
        message: "Teacher name updated successfully",
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error("❌ Error updating teacher name:", err);
      next(err);
    }
  }
);

app.put(
  "/api/teacher/:teacher_id/password",
  authenticateTeacher,
  async (req, res, next) => {
    const { teacher_id } = req.params;
    const { password } = req.body;
    if (!password || password.length < 6) {
      return res.status(400).json({
        status: "error",
        message: "Password must be at least 6 characters long",
        timestamp: new Date().toISOString(),
      });
    }
    try {
      const [result] = await becsPool.query(
        `UPDATE teachers
            SET password = ?
            WHERE teacher_id = ?`,
        [password, teacher_id]
      );
      if (result.affectedRows === 0) {
        return res.status(404).json({
          status: "error",
          message: "Teacher not found",
          timestamp: new Date().toISOString(),
        });
      }
      res.json({
        status: "success",
        message: "Password updated successfully",
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error("❌ Error updating password:", err);
      next(err);
    }
  }
);

// Notes Management Endpoints (BECS DB)
app.get(
  "/api/teacher/:teacher_id/notes",
  authenticateTeacher,
  async (req, res, next) => {
    const { teacher_id } = req.params;
    try {
      const [rows] = await becsPool.query(
        `
            SELECT n.id, n.note_name, n.no_of_pages, n.pdf_link, n.course_id, c.course_name
            FROM notes n
            JOIN courses c ON n.course_id = c.course_id
            JOIN teachers t ON t.course_id = c.course_id
            WHERE t.teacher_id = ?
        `,
        [teacher_id]
      );
      res.json({
        status: "success",
        count: rows.length,
        notes: rows,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error(`❌ Notes fetch error for teacher ${teacher_id}:`, error);
      if (error.code === "PROTOCOL_SEQUENCE_TIMEOUT") {
        return res.status(504).json({
          status: "error",
          message: "Database query timed out",
          error: error.message,
          timestamp: new Date().toISOString(),
        });
      } else if (
        error.code === "ETIMEDOUT" ||
        error.code === "PROTOCOL_CONNECTION_LOST"
      ) {
        return res.status(503).json({
          status: "error",
          message: "Database connection timed out",
          error: error.message,
          timestamp: new Date().toISOString(),
        });
      }
      next(error);
    }
  }
);

const { Storage } = require("@google-cloud/storage");
const storage = new Storage({
  keyFilename: "./INSTITUTE/student login/firebase-service-account.json",
});
const bucket = storage.bucket("becs-133d8.appspot.com");

app.post(
  "/api/teacher/:teacher_id/notes",
  authenticateTeacher,
  async (req, res, next) => {
    const { teacher_id } = req.params;
    const { note_name, no_of_pages, course_id, pdf_file } = req.body;
    if (!note_name || !course_id || !pdf_file) {
      return res.status(400).json({
        status: "error",
        message: "Note name, course ID, and PDF file are required",
        timestamp: new Date().toISOString(),
      });
    }
    try {
      const [teacherRows] = await becsPool.query(
        "SELECT course_id FROM teachers WHERE teacher_id = ?",
        [teacher_id]
      );
      if (
        teacherRows.length === 0 ||
        parseInt(teacherRows[0].course_id) !== parseInt(course_id)
      ) {
        return res.status(403).json({
          status: "error",
          message: "Not authorized to add notes for this course",
          timestamp: new Date().toISOString(),
        });
      }
      const fileName = `notes/${course_id}/${note_name}_${Date.now()}.pdf`;
      const file = bucket.file(fileName);
      const buffer = Buffer.from(pdf_file, "base64");
      await file.save(buffer, { contentType: "application/pdf" });
      const [url] = await file.getSignedUrl({
        action: "read",
        expires: "03-01-2500",
      });
      const [result] = await becsPool.query(
        "INSERT INTO notes (note_name, no_of_pages, pdf_link, course_id) VALUES (?, ?, ?, ?)",
        [note_name, no_of_pages || null, url, course_id]
      );
      res.json({
        status: "success",
        note_id: result.insertId,
        message: "Note added successfully",
        pdf_link: url,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error(`[${new Date().toISOString()}] ❌ Add note error:`, error);
      res.status(500).json({
        status: "error",
        message: error.message || "Failed to add note",
        timestamp: new Date().toISOString(),
      });
    }
  }
);

app.put(
  "/api/teacher/:teacher_id/notes/:note_id",
  authenticateTeacher,
  async (req, res, next) => {
    const { teacher_id, note_id } = req.params;
    const { note_name, no_of_pages, pdf_link, course_id } = req.body;
    if (!note_name || !course_id) {
      console.warn(
        `[${new Date().toISOString()}] ❌ Missing note_name or course_id in /api/teacher/${teacher_id}/notes/${note_id} PUT request`
      );
      return res.status(400).json({
        status: "error",
        message: "Note name and course ID are required",
        timestamp: new Date().toISOString(),
      });
    }
    try {
      const [teacherRows] = await becsPool.query(
        "SELECT course_id FROM teachers WHERE teacher_id = ?",
        [teacher_id]
      );
      if (
        teacherRows.length === 0 ||
        parseInt(teacherRows[0].course_id) !== parseInt(course_id)
      ) {
        console.warn(
          `[${new Date().toISOString()}] ❌ Teacher ${teacher_id} not authorized for course ${course_id}`
        );
        return res.status(403).json({
          status: "error",
          message: "Not authorized to edit notes for this course",
          timestamp: new Date().toISOString(),
        });
      }
      const [noteRows] = await becsPool.query(
        "SELECT course_id, no_of_pages, pdf_link FROM notes WHERE id = ?",
        [note_id]
      );
      if (noteRows.length === 0) {
        console.warn(
          `[${new Date().toISOString()}] ❌ Note ${note_id} not found`
        );
        return res.status(404).json({
          status: "error",
          message: "Note not found",
          timestamp: new Date().toISOString(),
        });
      }
      const [result] = await becsPool.query(
        "UPDATE notes SET note_name = ?, no_of_pages = ?, pdf_link = ?, course_id = ? WHERE id = ?",
        [
          note_name,
          no_of_pages || noteRows[0].no_of_pages,
          pdf_link || noteRows[0].pdf_link,
          course_id,
          note_id,
        ]
      );
      if (result.affectedRows > 0) {
        res.json({
          status: "success",
          message: "Note updated successfully",
          timestamp: new Date().toISOString(),
        });
      } else {
        console.warn(
          `[${new Date().toISOString()}] ❌ Note ${note_id} not found for update`
        );
        return res.status(404).json({
          status: "error",
          message: "Note not found",
          timestamp: new Date().toISOString(),
        });
      }
    } catch (error) {
      console.error(
        `❌ Update note error for teacher ${teacher_id}, note ${note_id}:`,
        error
      );
      next(error);
    }
  }
);

app.delete(
  "/api/teacher/:teacher_id/notes/:note_id",
  authenticateTeacher,
  async (req, res, next) => {
    const { teacher_id, note_id } = req.params;
    try {
      const [noteRows] = await becsPool.query(
        `
            SELECT n.course_id
            FROM notes n
            JOIN teachers t ON t.course_id = n.course_id
            WHERE n.id = ? AND t.teacher_id = ?
        `,
        [note_id, teacher_id]
      );
      if (noteRows.length === 0) {
        console.warn(
          `[${new Date().toISOString()}] ❌ Teacher ${teacher_id} not authorized to delete note ${note_id} or note not found`
        );
        return res.status(403).json({
          status: "error",
          message: "Not authorized to delete this note or note not found",
          timestamp: new Date().toISOString(),
        });
      }
      const [result] = await becsPool.query("DELETE FROM notes WHERE id = ?", [
        note_id,
      ]);
      if (result.affectedRows > 0) {
        res.json({
          status: "success",
          message: "Note deleted successfully",
          timestamp: new Date().toISOString(),
        });
      } else {
        console.warn(
          `[${new Date().toISOString()}] ❌ Note ${note_id} not found for deletion`
        );
        return res.status(404).json({
          status: "error",
          message: "Note not found",
          timestamp: new Date().toISOString(),
        });
      }
    } catch (error) {
      console.error(
        `❌ Delete note error for teacher ${teacher_id}, note ${note_id}:`,
        error
      );
      next(error);
    }
  }
);

// Error Handling & Security
app.use((err, req, res, next) => {
  console.error("❌ Unhandled error:", err);
  if (err.code === "ECONNRESET") {
    return res.status(503).json({
      error: "Service Unavailable",
      message: "Database connection was reset",
      details: err.message,
      timestamp: new Date().toISOString(),
    });
  } else if (err.code === "PROTOCOL_SEQUENCE_TIMEOUT") {
    return res.status(504).json({
      status: "error",
      message: "Database query timed out",
      error: err.message,
      timestamp: new Date().toISOString(),
    });
  } else if (
    err.code === "ETIMEDOUT" ||
    err.code === "PROTOCOL_CONNECTION_LOST"
  ) {
    return res.status(503).json({
      status: "error",
      message: "Database connection timed out",
      error: err.message,
      timestamp: new Date().toISOString(),
    });
  }
  res.status(500).json({
    error: "Internal Server Error",
    message: "An unexpected error occurred",
    details: err.message,
    timestamp: new Date().toISOString(),
  });
});

app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; " +
      "script-src 'self' https://www.gstatic.com https://www.youtube.com https://s.ytimg.com https://checkout.razorpay.com https://cdnjs.cloudflare.com; " +
      "frame-src https://www.youtube.com https://*.razorpay.com; " +
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src 'self' https://fonts.gstatic.com; " +
      "img-src 'self' data:; " +
      "connect-src 'self' http://localhost:3000 http://127.0.0.1:3000 http://localhost:3001 http://127.0.0.1:3001;"
  );
  next();
});

// Start Server
const server = app.listen(PORT, () => {
  console.log(`🚀 Combined Server running on http://localhost:${PORT}`);
});

server.on("error", (error) => {
  console.error("❌ Server failed to start:", error);
  process.exit(1);
});

server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;

// Graceful Shutdown
function gracefulShutdown(signal) {
  console.log(`\n🛑 Received ${signal}. Starting graceful shutdown...`);
  server.close(() => {
    console.log("✅ HTTP server closed");
    if (banerjeeDB) {
      banerjeeDB.end((err) => {
        if (err) console.error("❌ Error closing Banerjee DB connection:", err);
        else console.log("✅ Banerjee DB connection closed");
      });
    }
    if (banerjeePool) {
      banerjeePool.end((err) => {
        if (err) console.error("❌ Error closing Banerjee pool:", err);
        else console.log("✅ Banerjee pool closed");
      });
    }
    if (becsPool) {
      becsPool
        .end()
        .then(() => {
          console.log("✅ BECS pool closed");
          process.exit(0);
        })
        .catch((err) => {
          console.error("❌ Error closing BECS pool:", err);
          process.exit(1);
        });
    } else {
      process.exit(0);
    }
  });
  setTimeout(() => {
    console.error(
      "❌ Could not close connections in time, forcefully shutting down"
    );
    process.exit(1);
  }, 30000);
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("uncaughtException", (err) => {
  console.error("❌ Uncaught Exception:", err);
  gracefulShutdown("uncaughtException");
});
process.on("unhandledRejection", (reason, promise) => {
  console.error("❌ Unhandled Rejection at:", promise, "reason:", reason);
  gracefulShutdown("unhandledRejection");
});

// Additional Utility Endpoints
app.get("/api/stats", async (req, res) => {
  try {
    const stats = {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      platform: process.platform,
      nodeVersion: process.version,
      timestamp: new Date().toISOString(),
    };
    res.json({
      status: "success",
      stats,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("❌ Error fetching stats:", err);
    res.status(500).json({
      status: "error",
      message: "Failed to fetch server statistics",
      timestamp: new Date().toISOString(),
    });
  }
});

app.get("/api/db-status", async (req, res) => {
  try {
    const status = {
      banerjee: false,
      becs: false,
      timestamp: new Date().toISOString(),
    };
    try {
      const banerjeeConn = await mysql2Promise.createConnection(banerjeeConfig);
      await banerjeeConn.ping();
      await banerjeeConn.end();
      status.banerjee = true;
    } catch (err) {
      console.error("❌ Banerjee DB test failed:", err.message);
    }
    try {
      const becsConn = await becsPool.getConnection();
      await becsConn.ping();
      becsConn.release();
      status.becs = true;
    } catch (err) {
      console.error("❌ BECS DB test failed:", err.message);
    }
    res.json({
      status: "success",
      databases: status,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("❌ Error checking DB status:", err);
    res.status(500).json({
      status: "error",
      message: "Failed to check database status",
      timestamp: new Date().toISOString(),
    });
  }
});

app.get(
  "/api/user/:uid/course/:course_id/notes",
  authenticateFirebaseToken,
  async (req, res, next) => {
    const { uid, course_id } = req.params;
    if (uid !== req.user.uid) {
      console.warn(
        `[${new Date().toISOString()}] ❌ UID mismatch: requested(${uid}) vs authenticated(${
          req.user.uid
        })`
      );
      return res.status(403).json({
        status: "error",
        message: "You can only access your own resources",
        timestamp: new Date().toISOString(),
      });
    }
    if (!course_id || isNaN(course_id) || parseInt(course_id) <= 0) {
      console.warn(
        `[${new Date().toISOString()}] ❌ Invalid course_id: ${course_id}`
      );
      return res.status(400).json({
        status: "error",
        message: "Invalid course ID. Must be a positive integer.",
        timestamp: new Date().toISOString(),
      });
    }
    try {
      const [courseExists] = await becsPool.query(
        "SELECT course_id, course_name FROM courses WHERE course_id = ?",
        [course_id]
      );
      if (courseExists.length === 0) {
        console.warn(
          `[${new Date().toISOString()}] ❌ Course ${course_id} not found`
        );
        return res.status(404).json({
          status: "error",
          message: `Course with ID ${course_id} not found`,
          timestamp: new Date().toISOString(),
        });
      }
      const [purchaseExists] = await becsPool.query(
        "SELECT course_id FROM purchased_courses WHERE firebase_uid = ? AND course_id = ?",
        [uid, course_id]
      );
      if (purchaseExists.length === 0) {
        console.warn(
          `[${new Date().toISOString()}] ❌ User ${uid} has not purchased course ${course_id}`
        );
        return res.status(403).json({
          status: "error",
          message: "You have not purchased this course",
          timestamp: new Date().toISOString(),
        });
      }
      const [notes] = await becsPool.query(
        `
            SELECT n.id, n.note_name, n.no_of_pages, n.pdf_link, n.course_id, c.course_name
            FROM notes n
            JOIN courses c ON n.course_id = c.course_id
            WHERE n.course_id = ?
        `,
        [course_id]
      );
      res.json({
        status: "success",
        count: notes.length,
        notes,
        course_name: courseExists[0].course_name,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error(
        `[${new Date().toISOString()}] ❌ Error fetching notes for course ${course_id}:`,
        error
      );
      if (error.code === "PROTOCOL_SEQUENCE_TIMEOUT") {
        return res.status(504).json({
          status: "error",
          message: "Database query timed out",
          error: error.message,
          timestamp: new Date().toISOString(),
        });
      } else if (
        error.code === "ETIMEDOUT" ||
        error.code === "PROTOCOL_CONNECTION_LOST"
      ) {
        return res.status(503).json({
          status: "error",
          message: "Database connection timed out",
          error: error.message,
          timestamp: new Date().toISOString(),
        });
      }
      next(error);
    }
  }
);

// Notice Management Endpoints (BECS DB)
app.get("/api/notices", authenticateFirebaseToken, async (req, res, next) => {
  try {
    const [purchaseResults] = await becsPool.query(
      `SELECT course_id FROM purchased_courses WHERE firebase_uid = ?`,
      [req.user.uid]
    );
    if (purchaseResults.length === 0) {
      console.warn(
        `[${new Date().toISOString()}] ❌ User ${
          req.user.uid
        } has not purchased any courses`
      );
      return res.status(403).json({
        status: "error",
        message: "You must purchase a course to view notices",
        timestamp: new Date().toISOString(),
      });
    }
    const [results] = await becsPool.query(`
            SELECT id, title, description, link, type, status, created_at, updated_at
            FROM notices
            WHERE status = 'Active'
            ORDER BY created_at DESC
        `);
    res.json({
      status: "success",
      count: results.length,
      notices: results,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error(
      `[${new Date().toISOString()}] ❌ Error fetching notices for user ${
        req.user.uid
      }:`,
      err
    );
    if (err.code === "PROTOCOL_SEQUENCE_TIMEOUT") {
      return res.status(504).json({
        status: "error",
        message: "Database query timed out",
        error: err.message,
        timestamp: new Date().toISOString(),
      });
    } else if (
      err.code === "ETIMEDOUT" ||
      err.code === "PROTOCOL_CONNECTION_LOST"
    ) {
      return res.status(503).json({
        status: "error",
        message: "Database connection timed out",
        error: err.message,
        timestamp: new Date().toISOString(),
      });
    }
    next(err);
  }
});

app.get(
  "/api/teacher/:teacher_id/notices",
  authenticateTeacher,
  async (req, res, next) => {
    const { teacher_id } = req.params;
    const teacherId = parseInt(teacher_id);

    // Validate teacher_id
    if (isNaN(teacherId) || teacherId <= 0) {
      console.warn(
        `[${new Date().toISOString()}] ❌ Invalid teacher_id: ${teacher_id}`
      );
      return res.status(400).json({
        status: "error",
        message: "Invalid teacher ID. Must be a positive integer.",
        timestamp: new Date().toISOString(),
      });
    }

    try {
      const [results] = await becsPool.query(`
          SELECT 
              id AS notice_id, 
              title, 
              description AS content, 
              created_at AS posted_at,
              link,
              type,
              status
          FROM notices
          ORDER BY created_at DESC
      `);

      res.json({
        status: "success",
        count: results.length,
        notices: results.map((notice) => ({
          notice_id: notice.notice_id,
          title: notice.title,
          content: notice.content,
          posted_at: notice.posted_at,
          link: notice.link,
          type: notice.type,
          status: notice.status,
        })),
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error(
        `[${new Date().toISOString()}] ❌ Error fetching notices for teacher ${teacherId}:`,
        err
      );
      if (err.code === "ER_BAD_FIELD_ERROR") {
        return res.status(500).json({
          status: "error",
          message: "Database schema error: Invalid column in query",
          error: err.message,
          timestamp: new Date().toISOString(),
        });
      } else if (err.code === "PROTOCOL_SEQUENCE_TIMEOUT") {
        return res.status(504).json({
          status: "error",
          message: "Database query timed out",
          error: err.message,
          timestamp: new Date().toISOString(),
        });
      } else if (
        err.code === "ETIMEDOUT" ||
        err.code === "PROTOCOL_CONNECTION_LOST"
      ) {
        return res.status(503).json({
          status: "error",
          message: "Database connection timed out",
          error: err.message,
          timestamp: new Date().toISOString(),
        });
      }
      next(err);
    }
  }
);
app.post(
  "/api/teacher/:teacher_id/notices",
  authenticateTeacher,
  async (req, res, next) => {
    const { teacher_id } = req.params;
    const { title, description, link, type } = req.body;
    if (!title || !description || !type) {
      console.warn(
        `[${new Date().toISOString()}] ❌ Missing required fields in /api/teacher/${teacher_id}/notices POST request`
      );
      return res.status(400).json({
        status: "error",
        message: "Title, description, and type are required",
        timestamp: new Date().toISOString(),
      });
    }
    try {
      const [result] = await becsPool.query(
        `INSERT INTO notices (teacher_id, title, description, link, type, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'Active', NOW(), NOW())`,
        [teacher_id, title, description, link || null, type]
      );
      res.json({
        status: "success",
        message: "Notice added successfully",
        notice_id: result.insertId,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error(
        `[${new Date().toISOString()}] ❌ Error adding notice for teacher ${teacher_id}:`,
        err
      );
      if (err.code === "ER_NO_REFERENCED_ROW_2") {
        return res.status(400).json({
          status: "error",
          message: "Invalid teacher ID",
          timestamp: new Date().toISOString(),
        });
      }
      next(err);
    }
  }
);

app.put(
  "/api/teacher/:teacher_id/notices/:notice_id",
  authenticateTeacher,
  async (req, res, next) => {
    const { teacher_id, notice_id } = req.params;
    const { title, description, link, type, status } = req.body;
    if (!title || !description || !type || !status) {
      console.warn(
        `[${new Date().toISOString()}] ❌ Missing required fields in /api/teacher/${teacher_id}/notices/${notice_id} PUT request`
      );
      return res.status(400).json({
        status: "error",
        message: "Title, description, type, and status are required",
        timestamp: new Date().toISOString(),
      });
    }
    try {
      const [result] = await becsPool.query(
        `UPDATE notices
            SET title = ?, description = ?, link = ?, type = ?, status = ?, updated_at = NOW()
            WHERE id = ? AND teacher_id = ?`,
        [title, description, link || null, type, status, notice_id, teacher_id]
      );
      if (result.affectedRows === 0) {
        console.warn(
          `[${new Date().toISOString()}] ❌ Notice ${notice_id} not found or teacher ${teacher_id} not authorized`
        );
        return res.status(404).json({
          status: "error",
          message: "Notice not found or you are not authorized to edit it",
          timestamp: new Date().toISOString(),
        });
      }
      res.json({
        status: "success",
        message: "Notice updated successfully",
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error(
        `[${new Date().toISOString()}] ❌ Error updating notice ${notice_id} for teacher ${teacher_id}:`,
        err
      );
      next(err);
    }
  }
);

app.delete(
  "/api/teacher/:teacher_id/notices/:notice_id",
  authenticateTeacher,
  async (req, res, next) => {
    const { teacher_id, notice_id } = req.params;
    try {
      const [result] = await becsPool.query(
        `DELETE FROM notices WHERE id = ? AND teacher_id = ?`,
        [notice_id, teacher_id]
      );
      if (result.affectedRows === 0) {
        console.warn(
          `[${new Date().toISOString()}] ❌ Notice ${notice_id} not found or teacher ${teacher_id} not authorized`
        );
        return res.status(404).json({
          status: "error",
          message: "Notice not found or you are not authorized to delete it",
          timestamp: new Date().toISOString(),
        });
      }
      res.json({
        status: "success",
        message: "Notice deleted successfully",
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error(
        `[${new Date().toISOString()}] ❌ Error deleting notice ${notice_id} for teacher ${teacher_id}:`,
        err
      );
      next(err);
    }
  }
);

// Admin Panel Endpoints (BECS DB)
app.post("/api/admin/login", async (req, res, next) => {
  const { admin_id, password } = req.body;
  if (!admin_id || !password) {
    console.warn(
      `[${new Date().toISOString()}] ❌ Missing admin_id or password in /api/admin/login request`
    );
    return res.status(400).json({
      status: "error",
      message: "Admin ID and password are required",
      timestamp: new Date().toISOString(),
    });
  }
  try {
    const [results] = await becsPool.query(
      `SELECT admin_id, password FROM admins WHERE admin_id = ?`,
      [admin_id]
    );
    if (results.length === 0 || results[0].password !== password) {
      console.warn(
        `[${new Date().toISOString()}] ❌ Invalid admin credentials for admin_id: ${admin_id}`
      );
      return res.status(401).json({
        status: "error",
        message: "Invalid admin ID or password",
        timestamp: new Date().toISOString(),
      });
    }
    res.json({
      status: "success",
      message: "Admin login successful",
      admin_id,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error(
      `[${new Date().toISOString()}] ❌ Error during admin login:`,
      err
    );
    next(err);
  }
});

app.get("/api/admin/courses", async (req, res, next) => {
  try {
    const [results] = await becsPool.query(`
            SELECT course_id, course_name, course_description, price, image_link, created_at, updated_at
            FROM courses
            ORDER BY course_id DESC
        `);
    res.json({
      status: "success",
      count: results.length,
      courses: results,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error(
      `[${new Date().toISOString()}] ❌ Error fetching courses for admin:`,
      err
    );
    if (err.code === "PROTOCOL_SEQUENCE_TIMEOUT") {
      return res.status(504).json({
        status: "error",
        message: "Database query timed out",
        error: err.message,
        timestamp: new Date().toISOString(),
      });
    } else if (
      err.code === "ETIMEDOUT" ||
      err.code === "PROTOCOL_CONNECTION_LOST"
    ) {
      return res.status(503).json({
        status: "error",
        message: "Database connection timed out",
        error: err.message,
        timestamp: new Date().toISOString(),
      });
    }
    next(err);
  }
});

app.post("/api/admin/courses", async (req, res, next) => {
  const { course_name, course_description, price, image_link } = req.body;
  if (!course_name || !course_description || !price || !image_link) {
    console.warn(
      `[${new Date().toISOString()}] ❌ Missing required fields in /api/admin/courses POST request`
    );
    return res.status(400).json({
      status: "error",
      message: "Course name, description, price, and image link are required",
      timestamp: new Date().toISOString(),
    });
  }
  try {
    const [result] = await becsPool.query(
      `INSERT INTO courses (course_name, course_description, price, image_link, created_at, updated_at)
            VALUES (?, ?, ?, ?, NOW(), NOW())`,
      [course_name, course_description, price, image_link]
    );
    res.json({
      status: "success",
      message: "Course added successfully",
      course_id: result.insertId,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error(`[${new Date().toISOString()}] ❌ Error adding course:`, err);
    next(err);
  }
});

app.put("/api/admin/courses/:course_id", async (req, res, next) => {
  const { course_id } = req.params;
  const { course_name, course_description, price, image_link } = req.body;
  if (!course_name || !course_description || !price || !image_link) {
    console.warn(
      `[${new Date().toISOString()}] ❌ Missing required fields in /api/admin/courses/${course_id} PUT request`
    );
    return res.status(400).json({
      status: "error",
      message: "Course name, description, price, and image link are required",
      timestamp: new Date().toISOString(),
    });
  }
  try {
    const [result] = await becsPool.query(
      `UPDATE courses
            SET course_name = ?, course_description = ?, price = ?, image_link = ?, updated_at = NOW()
            WHERE course_id = ?`,
      [course_name, course_description, price, image_link, course_id]
    );
    if (result.affectedRows === 0) {
      console.warn(
        `[${new Date().toISOString()}] ❌ Course ${course_id} not found`
      );
      return res.status(404).json({
        status: "error",
        message: "Course not found",
        timestamp: new Date().toISOString(),
      });
    }
    res.json({
      status: "success",
      message: "Course updated successfully",
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error(
      `[${new Date().toISOString()}] ❌ Error updating course ${course_id}:`,
      err
    );
    next(err);
  }
});

app.delete("/api/admin/courses/:course_id", async (req, res, next) => {
  const { course_id } = req.params;
  try {
    const [result] = await becsPool.query(
      `DELETE FROM courses WHERE course_id = ?`,
      [course_id]
    );
    if (result.affectedRows === 0) {
      console.warn(
        `[${new Date().toISOString()}] ❌ Course ${course_id} not found`
      );
      return res.status(404).json({
        status: "error",
        message: "Course not found",
        timestamp: new Date().toISOString(),
      });
    }
    res.json({
      status: "success",
      message: "Course deleted successfully",
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error(
      `[${new Date().toISOString()}] ❌ Error deleting course ${course_id}:`,
      err
    );
    next(err);
  }
});

// Additional Security Middleware
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  next();
});

// Catch-All Route for 404
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

// End of Code
