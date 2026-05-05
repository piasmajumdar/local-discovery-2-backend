const express = require('express');
const { MongoClient } = require('mongodb');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Resend } = require('resend');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;
const resend = new Resend(process.env.RESEND_API_KEY);

app.use(cors());
app.use(express.json());

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

async function start() {
    try {
        await client.connect();
        console.log("Connected to MongoDB Atlas");
        const db = client.db(process.env.MONGODB_DB);
        
        const shopsCol = db.collection('shops');
        const usersCol = db.collection('users');
        const countersCol = db.collection('counters');

        // Indexes
        await usersCol.createIndex({ email: 1 }, { unique: true });
        // Make userId index sparse so unverified users (with no userId yet) don't conflict
        try {
            await usersCol.dropIndex("userId_1");
        } catch (e) {
            // Index might not exist yet
        }
        await usersCol.createIndex({ userId: 1 }, { unique: true, sparse: true });

        // Helper: Generate Unique User ID
        async function getNextUserId() {
            const result = await countersCol.findOneAndUpdate(
                { _id: 'userId' },
                { $inc: { seq: 1 } },
                { upsert: true, returnDocument: 'after' }
            );
            return result.seq;
        }

        // --- SHOP ROUTES ---
        app.get('/api/shops', async (req, res) => {
            try {
                const { lat, lng, radius } = req.query;
                if (!lat || !lng) {
                    const shops = await shopsCol.find({}).limit(100).toArray();
                    return res.json(shops);
                }
                const latitude = parseFloat(lat);
                const longitude = parseFloat(lng);
                const maxDistance = parseInt(radius) || 40000;

                const shops = await shopsCol.find({
                    location: {
                        $near: {
                            $geometry: { type: "Point", coordinates: [longitude, latitude] },
                            $maxDistance: maxDistance
                        }
                    }
                }).toArray();
                res.json(shops);
            } catch (err) {
                res.status(500).json({ error: "Internal Server Error" });
            }
        });

        app.get('/api/categories', async (req, res) => {
            try {
                const categoriesCol = db.collection('categories');
                const categories = await categoriesCol.find({}).toArray();
                res.json(categories);
            } catch (err) {
                res.status(500).json({ error: "Failed to fetch categories" });
            }
        });

        // --- AUTH ROUTES ---

        // 1. SIGNUP
        app.post('/api/auth/signup', async (req, res) => {
            const { fullName, email, password } = req.body;

            try {
                const existingUser = await usersCol.findOne({ email });
                if (existingUser && existingUser.isVerified) {
                    return res.status(400).json({ error: "Email already registered." });
                }

                const hashedPassword = await bcrypt.hash(password, 10);
                const otp = Math.floor(100000 + Math.random() * 900000).toString();
                const otpExpires = new Date(Date.now() + 10 * 60000);

                // Upsert unverified user
                await usersCol.updateOne(
                    { email },
                    { 
                        $set: { 
                            fullName, 
                            password: hashedPassword, 
                            otp, 
                            otpExpires, 
                            isVerified: false,
                            photo: "", // Placeholder for Cloudinary URL
                            addedShops: [], 
                            myReviews: [],
                            role: "user",
                            createdAt: new Date()
                        } 
                    },
                    { upsert: true }
                );

                console.log("Attempting to send email from:", process.env.SENDER_EMAIL || 'onboarding@resend.dev');
                const { data, error } = await resend.emails.send({
                    from: process.env.SENDER_EMAIL || 'Local Discovery <onboarding@resend.dev>',
                    to: [email],
                    subject: 'Verify your Local Discovery Account',
                    html: `<div style="font-family: sans-serif; padding: 20px;">
                            <h2>Welcome!</h2>
                            <p>Your verification code is: <b>${otp}</b></p>
                           </div>`
                });

                if (error) {
                    console.error("Resend API Error:", error);
                    return res.status(500).json({ error: "Email failed." });
                }

                console.log("Email sent successfully:", data);
                res.status(200).json({ message: "OTP sent!" });
            } catch (err) {
                console.error("Signup Database/Logic Error:", err);
                res.status(500).json({ error: "Signup failed." });
            }
        });

        // 2. VERIFY OTP
        app.post('/api/auth/verify-otp', async (req, res) => {
            const { email, otp } = req.body;
            try {
                const user = await usersCol.findOne({ email });
                if (!user || user.otp !== otp || new Date() > user.otpExpires) {
                    return res.status(400).json({ error: "Invalid or expired OTP." });
                }

                // First time verification: Assign a unique numeric userId
                const userId = await getNextUserId();

                await usersCol.updateOne(
                    { email },
                    { 
                        $set: { isVerified: true, userId },
                        $unset: { otp: "", otpExpires: "" }
                    }
                );

                res.status(200).json({ message: "Verified!" });
            } catch (err) {
                res.status(500).json({ error: "Verification failed." });
            }
        });

        // 3. LOGIN
        app.post('/api/auth/login', async (req, res) => {
            const { email, password } = req.body;
            try {
                const user = await usersCol.findOne({ email });
                if (!user || !user.isVerified) {
                    return res.status(400).json({ error: "User not found or unverified." });
                }

                const isMatch = await bcrypt.compare(password, user.password);
                if (!isMatch) {
                    return res.status(400).json({ error: "Invalid credentials." });
                }

                // Generate JWT
                const token = jwt.sign(
                    { id: user._id, userId: user.userId, email: user.email },
                    process.env.JWT_SECRET,
                    { expiresIn: '7d' }
                );

                // Return User data (excluding password)
                const { password: _, otp: __, otpExpires: ___, ...userData } = user;
                res.json({ token, user: userData });
            } catch (err) {
                res.status(500).json({ error: "Login failed." });
            }
        });

        app.listen(port, () => {
            console.log(`Backend running at http://localhost:${port}`);
        });

    } catch (err) {
        console.error("Connection Error:", err);
    }
}

start();
