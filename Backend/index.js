import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";
import crypto from "crypto";
import User from "./models/User.js";

dotenv.config();

const app = express();
app.use(express.json());

// ==========================
// 🌍 CORS Configuration
// ==========================
app.use(
  cors({
    origin: ["http://localhost:5173"], // Update with your frontend URL
    methods: ["GET", "POST"],
    credentials: true,
  })
);

// ==========================
// 🔗 MongoDB Connection (Fixed Warnings)
// ==========================
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ Database Connection Error:", err));

// ==========================
// 📌 Root Route (Server Status Check)
// ==========================
app.get("/", (req, res) => {
  res.send("✅ Backend is running...");
});

// ==========================
// 🔹 Register User
// ==========================
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "✅ User registered successfully!" });
  } catch (error) {
    console.error("Register Error:", error);
    res.status(500).json({ message: "❌ Server error", error });
  }
});

// ==========================
// 🔹 Login User
// ==========================
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    res.status(200).json({ message: "✅ Login successful!", name: user.name });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: "❌ Server error", error });
  }
});

// ==========================
// 🔹 Forgot Password Route
// ==========================
app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    // Generate Reset Token
    const resetToken = crypto.randomBytes(32).toString("hex");
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // Token expires in 1 hour
    await user.save();

    // Send Reset Email
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER, // Your email from .env
        pass: process.env.EMAIL_PASS, // Your email password from .env
      },
    });

    const resetURL = `http://localhost:5173/reset-password?token=${resetToken}`;
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: "Password Reset Request",
      text: `Click the link to reset your password: ${resetURL}`,
    };

    await transporter.sendMail(mailOptions);

    res.json({ message: "✅ Reset link sent to your email!" });
  } catch (error) {
    console.error("Forgot Password Error:", error);
    res.status(500).json({ message: "❌ Server error", error });
  }
});

// ==========================
// 🔹 Reset Password Route
// ==========================
app.post("/api/auth/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }, // Check if token is valid
    });

    if (!user) return res.status(400).json({ message: "Invalid or expired token" });

    // Hash New Password
    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: "✅ Password reset successfully!" });
  } catch (error) {
    console.error("Reset Password Error:", error);
    res.status(500).json({ message: "❌ Server error", error });
  }
});

// ==========================
// 🚀 Start Server
// ==========================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
