const express = require('express');
const { MongoClient } = require('mongodb');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Resend } = require('resend');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;
const resend = new Resend(process.env.RESEND_API_KEY);

// Multer Configuration (Memory Storage)
const storage = multer.memoryStorage();
const upload = multer({ storage });

app.use(cors());
app.use(express.json());

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

// --- MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access denied. Token missing." });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid or expired token." });
        req.user = user;
        next();
    });
};

async function start() {
    try {
        // Cloudinary Configuration
        cloudinary.config({
            cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
            api_key: process.env.CLOUDINARY_API_KEY,
            api_secret: process.env.CLOUDINARY_API_SECRET
        });


        await client.connect();
        console.log("Connected to MongoDB Atlas");
        const db = client.db(process.env.MONGODB_DB);
        console.log("📂 Target Database:", db.databaseName);

        const shopsCol = db.collection('shops');
        const usersCol = db.collection('users');
        const countersCol = db.collection('counters');

        // Helper: Sync Shop ID Counter with existing data
        async function syncShopCounter() {
            const lastShop = await shopsCol.find().sort({ id: -1 }).limit(1).toArray();
            if (lastShop.length > 0) {
                const highestId = lastShop[0].id;
                await countersCol.updateOne(
                    { _id: 'shopId' },
                    { $set: { seq: highestId } },
                    { upsert: true }
                );
                console.log(`📡 Shop ID counter synchronized to: ${highestId}`);
            }
        }
        await syncShopCounter();

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

        async function getNextShopId() {
            const result = await countersCol.findOneAndUpdate(
                { _id: 'shopId' },
                { $inc: { seq: 1 } },
                { upsert: true, returnDocument: 'after' }
            );
            return result.seq;
        }

        async function getNextReviewId() {
            const result = await countersCol.findOneAndUpdate(
                { _id: 'reviewId' },
                { $inc: { seq: 1 } },
                { upsert: true, returnDocument: 'after' }
            );
            return result.seq;
        }

        // --- SHOP ROUTES ---
        app.get('/api/shops', async (req, res) => {
            try {
                const { lat, lng, radius } = req.query;
                const query = { isVerifiedByAdmin: true };

                if (lat && lng) {
                    const latitude = parseFloat(lat);
                    const longitude = parseFloat(lng);
                    const maxDistance = parseInt(radius) || 40000;
                    query.location = {
                        $near: {
                            $geometry: { type: "Point", coordinates: [longitude, latitude] },
                            $maxDistance: maxDistance
                        }
                    };
                }

                const shops = await shopsCol.find(query).limit(100).toArray();
                res.json(shops);
            } catch (err) {
                console.error("Fetch shops error:", err);
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

        // 4. GET CURRENT USER
        app.get('/api/auth/me', authenticateToken, async (req, res) => {
            try {
                const user = await usersCol.findOne({ email: req.user.email });
                if (!user) {
                    return res.status(404).json({ error: "User not found." });
                }

                // Fetch actual shop documents for the IDs in addedShops
                const myShops = await shopsCol.find({ 
                    id: { $in: user.addedShops || [] } 
                }).toArray();

                // Return User data (including populated shops)
                const { password, otp, otpExpires, ...userData } = user;
                res.json({ ...userData, myShops });
            } catch (err) {
                console.error("Profile fetch error:", err);
                res.status(500).json({ error: "Failed to fetch profile." });
            }
        });

        // --- FINAL SHOP LISTING ROUTE ---
        app.post('/api/shops/add', upload.array('images'), async (req, res) => {
            try {
                const shopData = req.body.shopData ? JSON.parse(req.body.shopData) : req.body;
                
                // Get the official next shop ID
                const shopId = await getNextShopId();
                shopData.id = shopId;

                const uploadedUrls = [];
                for (let i = 0; i < req.files.length; i++) {
                    const file = req.files[i];
                    const b64 = Buffer.from(file.buffer).toString("base64");
                    let dataURI = "data:" + file.mimetype + ";base64," + b64;

                    const result = await cloudinary.uploader.upload(dataURI, {
                        folder: `shops/id_${shopId}`,
                        public_id: `${i + 1}`,
                        overwrite: true,
                        transformation: [
                            { width: 1000, crop: "limit" },
                            { quality: "auto" },
                            { fetch_format: "auto" }
                        ]
                    });
                    uploadedUrls.push(result.secure_url);
                }

                shopData.images = uploadedUrls;
                shopData.coverImg = uploadedUrls[0] || '';

                // 1. Save Shop to MongoDB
                const insertResult = await shopsCol.insertOne(shopData);
                console.log("📝 MongoDB Insert Result:", insertResult);

                // 2. Update User's 'addedShops' list
                if (shopData.userId && shopData.userId !== 'guest') {
                    await usersCol.updateOne(
                        { userId: shopData.userId },
                        { $push: { addedShops: shopId } }
                    );
                }

                console.log(`✅ Shop #${shopId} added successfully by User #${shopData.userId}`);
                res.json({ success: true, message: "Shop listed successfully!", id: shopId });

            } catch (err) {
                console.error("❌ Shop Listing Error:", err);
                res.status(500).json({ error: "Failed to list shop." });
            }
        });

        // --- ADMIN MIDDLEWARE ---
        const isAdmin = async (req, res, next) => {
            try {
                const user = await usersCol.findOne({ email: req.user.email });
                if (user && user.role === 'admin') {
                    next();
                } else {
                    res.status(403).json({ error: "Access denied. Admins only." });
                }
            } catch (err) {
                res.status(500).json({ error: "Admin check failed." });
            }
        };

        // --- ADMIN ROUTES ---

        // 1. Get Overall Stats
        app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
            try {
                const totalShops = await shopsCol.countDocuments();
                const pendingShops = await shopsCol.countDocuments({ isVerifiedByAdmin: false });
                const totalUsers = await usersCol.countDocuments();
                
                // Group shops by category for analytics
                const categoryStats = await shopsCol.aggregate([
                    { $group: { _id: "$category", count: { $sum: 1 } } },
                    { $sort: { count: -1 } }
                ]).toArray();

                res.json({
                    totalShops,
                    pendingShops,
                    totalUsers,
                    categoryStats
                });
            } catch (err) {
                res.status(500).json({ error: "Failed to fetch admin stats." });
            }
        });

        // 2. Get Pending Shops
        app.get('/api/admin/pending-shops', authenticateToken, isAdmin, async (req, res) => {
            try {
                const shops = await shopsCol.find({ isVerifiedByAdmin: false }).toArray();
                res.json(shops);
            } catch (err) {
                res.status(500).json({ error: "Failed to fetch pending shops." });
            }
        });

        // 3. Approve a Shop
        app.post('/api/admin/approve-shop/:id', authenticateToken, isAdmin, async (req, res) => {
            try {
                const shopId = parseInt(req.params.id);
                const result = await shopsCol.updateOne(
                    { id: shopId },
                    { $set: { isVerifiedByAdmin: true } }
                );

                if (result.modifiedCount === 0) {
                    return res.status(404).json({ error: "Shop not found or already verified." });
                }

                res.json({ success: true, message: "Shop approved successfully!" });
            } catch (err) {
                res.status(500).json({ error: "Approval failed." });
            }
        });

        // 4. Get All Shops (Admin Only)
        app.get('/api/admin/all-shops', authenticateToken, isAdmin, async (req, res) => {
            try {
                const shops = await shopsCol.find({}).sort({ id: -1 }).toArray();
                res.json(shops);
            } catch (err) {
                res.status(500).json({ error: "Failed to fetch all shops." });
            }
        });

        // 5. Get All Users (Admin Only)
        app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
            try {
                const users = await usersCol.find({}).project({ password: 0 }).sort({ fullName: 1 }).toArray();
                res.json(users);
            } catch (err) {
                res.status(500).json({ error: "Failed to fetch users." });
            }
        });

        // 6. Delete Shop (Admin Only)
        app.delete('/api/admin/shop/:id', authenticateToken, isAdmin, async (req, res) => {
            try {
                const shopId = parseInt(req.params.id);
                const result = await shopsCol.deleteOne({ id: shopId });
                if (result.deletedCount === 0) return res.status(404).json({ error: "Shop not found" });
                res.json({ message: "Shop permanently deleted." });
            } catch (err) {
                res.status(500).json({ error: "Failed to delete shop." });
            }
        });

        // 7. Delete User (Admin Only)
        app.delete('/api/admin/user/:id', authenticateToken, isAdmin, async (req, res) => {
            try {
                const userId = req.params.id;
                const result = await usersCol.deleteOne({ _id: new (require('mongodb').ObjectId)(userId) });
                if (result.deletedCount === 0) return res.status(404).json({ error: "User not found" });
                res.json({ message: "User permanently removed." });
            } catch (err) {
                res.status(500).json({ error: "Failed to delete user." });
            }
        });

        // --- PUBLIC REVIEW ROUTES ---
        app.post('/api/shops/:id/review', authenticateToken, upload.array('photos'), async (req, res) => {
            try {
                const shopId = parseInt(req.params.id);
                const { rating, text } = req.body;
                const user = await usersCol.findOne({ email: req.user.email });

                if (!user) return res.status(404).json({ error: "User not found" });

                const reviewId = await getNextReviewId();
                const uploadedUrls = [];

                // 1. Upload Photos to Cloudinary
                if (req.files && req.files.length > 0) {
                    for (let i = 0; i < req.files.length; i++) {
                        const file = req.files[i];
                        const b64 = Buffer.from(file.buffer).toString("base64");
                        let dataURI = "data:" + file.mimetype + ";base64," + b64;

                        const result = await cloudinary.uploader.upload(dataURI, {
                            folder: `shops/id_${shopId}/reviews`,
                            public_id: `rev_${reviewId}_${i + 1}`,
                            overwrite: true,
                            transformation: [
                                { width: 1000, crop: "limit" },
                                { quality: "auto" },
                                { fetch_format: "auto" }
                            ]
                        });
                        uploadedUrls.push(result.secure_url);
                    }
                }

                const newReview = {
                    id: reviewId,
                    userId: user.userId,
                    name: user.fullName,
                    init: user.fullName.charAt(0).toUpperCase(),
                    rating: parseInt(rating),
                    date: "Just now",
                    text: text,
                    photos: uploadedUrls,
                    helpful: 0,
                    voted: false
                };

                console.log("\n🚀 --- POSTING NEW REVIEW ---");
                console.log(`📍 Shop ID: ${shopId}`);
                console.log(`👤 User: ${user.fullName} (ID: ${user.userId})`);
                console.log(`📝 Review Content: "${text}"`);
                console.log(`⭐ Rating: ${rating}`);
                console.log(`🖼️ Photos Attached: ${uploadedUrls.length}`);
                
                // 2. Update Shop Collection
                const shopUpdate = {
                    $push: { 
                        reviews: { $each: [newReview], $position: 0 },
                        images: { $each: uploadedUrls } 
                    }
                };

                // Check if coverImg needs setting
                const targetShop = await shopsCol.findOne({ id: shopId });
                if (targetShop && (!targetShop.coverImg || targetShop.coverImg === '') && uploadedUrls.length > 0) {
                    shopUpdate.$set = { coverImg: uploadedUrls[0] };
                    console.log(`🖼️ Setting first review photo as coverImg for Shop #${shopId}`);
                }

                await shopsCol.updateOne({ id: shopId }, shopUpdate);

                // 3. Update User Collection
                await usersCol.updateOne(
                    { userId: user.userId },
                    { $push: { myReviews: reviewId } }
                );

                console.log(`✅ Database modified successfully for Shop #${shopId} and User #${user.userId}\n`);

                res.json({ success: true, review: newReview });

            } catch (err) {
                console.error("Review posting error:", err);
                res.status(500).json({ error: "Failed to post review." });
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
