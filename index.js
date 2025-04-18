const express = require("express");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const dotenv = require("dotenv");
const session = require("express-session");
const mongoose = require("mongoose");
const MongoStore = require("connect-mongo");
const axios = require('axios');
const cors = require('cors');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(cors({
    origin: true,
    credentials: true
}));

// Database connection
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/medico";

// Session configuration
app.use(
    session({
        secret: process.env.SESSION_SECRET || "yourSecretKey",
        resave: false,
        saveUninitialized: false,
        store: MongoStore.create({
            mongoUrl: MONGO_URI,
            ttl: 24 * 60 * 60,
            autoRemove: 'native'
        }),
        cookie: { 
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: true
        }
    })
);

// Connect to MongoDB
async function connectDB() {
    try {
        console.log('🔗 Connecting to MongoDB...');
        await mongoose.connect(MONGO_URI, {
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
            connectTimeoutMS: 30000
        });
        console.log('🏓 MongoDB connected successfully');
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        process.exit(1);
    }
}
connectDB();

// User Schema and Model
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { 
        type: String, 
        required: true, 
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^\S+@\S+\.\S+$/, "Please use a valid email address"]
    },
    password: { type: String, required: true, minlength: 6 },
    gender: { type: String, enum: ["Male", "Female", "Other"], default: "Other" },
    age: { type: Number, min: 1 },
    height: { type: Number, min: 30 },
    weight: { type: Number, min: 1 },
    activityLevel: { 
        type: String, 
        enum: ["sedentary", "lightlyActive", "moderatelyActive", "veryActive", "extraActive"],
        default: "sedentary"
    },
    lastPasswordChange: { type: Date, default: Date.now }
}, { timestamps: true });

// Password hashing middleware
UserSchema.pre("save", async function(next) {
    if (!this.isModified("password")) return next();
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        this.lastPasswordChange = Date.now();
        next();
    } catch (error) {
        next(error);
    }
});

// Password comparison method
UserSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword.trim(), this.password);
};

const User = mongoose.model("User", UserSchema);

// OTC Medicines database
const OTC_MEDICINES = {
    headache: [
        { name: "Acetaminophen (Tylenol)", dosage: "500mg every 4-6 hours", max: "4000mg/day" },
        { name: "Ibuprofen (Advil, Motrin)", dosage: "200-400mg every 4-6 hours", max: "1200mg/day" }
    ],
    fever: [
        { name: "Acetaminophen (Tylenol)", dosage: "500mg every 4-6 hours", max: "4000mg/day" }
    ],
    sore_throat: [
        { name: "Chloraseptic spray", dosage: "Spray every 2 hours as needed" }
    ],
    common_cold: [
        { name: "Pseudoephedrine (Sudafed)", dosage: "30-60mg every 4-6 hours" }
    ],
    // Add more medicine categories as needed
};

// Infermedica API configuration
const INFERMEDICA_APP_ID = process.env.INFERMEDICA_APP_ID;
const INFERMEDICA_APP_KEY = process.env.INFERMEDICA_APP_KEY;
const INFERMEDICA_API_URL = 'https://api.infermedica.com/v3/';

// Helper functions
function getChoiceId(severity) {
    return severity > 2 ? 'present' : severity > 1 ? 'present' : 'absent';
}

function getSeverity(probability) {
    if (probability > 0.7) return 'high';
    if (probability > 0.3) return 'medium';
    return 'low';
}

function mapConditionToOTCKey(conditionName) {
    const mappings = {
        'common cold': 'common_cold',
        'headache': 'headache',
        'fever': 'fever',
        'sore throat': 'sore_throat'
        // Add more mappings as needed
    };
    return mappings[conditionName.toLowerCase()] || null;
}

// Session validation middleware
async function validateSession(req, res, next) {
    if (!req.session.user) {
        console.log("No session user - redirecting to login");
        return res.redirect("/");
    }
    
    try {
        const user = await User.findOne({ email: req.session.user.email });
        if (!user) {
            console.log("User not found in DB - destroying session");
            req.session.destroy();
            return res.redirect("/");
        }
        req.user = user;
        console.log("Session validated for user:", user.email);
        next();
    } catch (error) {
        console.error("Session validation error:", error);
        res.status(500).send("Server error");
    }
}
function getDoctorSpecialty(conditionName) {
    const specialties = {
        'headache': 'neurologist',
        'fever': 'general practitioner',
        'sore throat': 'ENT specialist',
        'chest pain': 'cardiologist',
        'abdominal pain': 'gastroenterologist',
        // Add more mappings as needed
    };
    return specialties[conditionName.toLowerCase()] || 'general practitioner';
}


// Routes
app.get("/", (req, res) => res.render("Login"));
app.get("/signup", (req, res) => res.render("Signup"));
// app.get("/home", validateSession, async (req, res) => {
//     try {
//         const user = req.user;
//         const bmi = (user.weight / ((user.height / 100) ** 2)).toFixed(2);
//         res.render("Home", { user, bmi });
//     } catch (error) {
//         res.status(500).send("Error fetching user data");
//     }
// });

// Symptom Checker Route
app.post("/check-symptoms", validateSession, async (req, res) => {
    try {
        const { symptoms, symptomDetails, userInfo } = req.body;
        
        if (!symptoms || symptoms.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: "Please select symptoms" 
            });
        }

        // Validate Infermedica credentials
        if (!INFERMEDICA_APP_ID || !INFERMEDICA_APP_KEY) {
            console.error("Infermedica credentials not configured");
            return res.status(500).json({ 
                success: false, 
                message: "Diagnosis service not configured" 
            });
        }

        const evidence = symptoms.map(symptomId => {
            const detail = symptomDetails.find(d => d.id === symptomId) || {};
            return {
                id: symptomId,
                choice_id: getChoiceId(detail.severity),
                initial: true
            };
        });

        const requestData = {
            sex: (userInfo.gender || 'male').toLowerCase(),
            age: { value: userInfo.age || 30 },
            evidence,
            extras: { disable_groups: true }
        };

        console.log("Sending to Infermedica:", requestData);
        
        const response = await axios.post(`${INFERMEDICA_API_URL}diagnosis`, requestData, {
            headers: {
                'App-Id': INFERMEDICA_APP_ID,
                'App-Key': INFERMEDICA_APP_KEY,
                'Content-Type': 'application/json'
            },
            timeout: 10000
        });

        if (!response.data || !response.data.conditions) {
            console.error("Unexpected response format from Infermedica");
            return res.status(500).json({ 
                success: false, 
                message: "Unexpected response from diagnosis service" 
            });
        }

        const conditions = response.data.conditions.map(cond => {
            const otcKey = mapConditionToOTCKey(cond.common_name);
            const severity = getSeverity(cond.probability);
            
            return {
                id: cond.id,
                name: cond.common_name,
                probability: cond.probability,
                severity: severity,
                medicines: otcKey ? OTC_MEDICINES[otcKey] || [] : [],
                needsDoctor: cond.probability > 0.3, // Adjust threshold as needed
                doctorInfo: {
                    specialty: getDoctorSpecialty(cond.common_name),
                    urgency: severity === 'high' ? 'within 24 hours' : 
                            severity === 'medium' ? 'within 3 days' : 'when convenient'
                }
            };
        });

        res.json({ 
            success: true, 
            conditions 
        });
    } catch (error) {
        console.error("Error in symptom analysis:", error);
        let message = "Server error";
        if (error.response) {
            console.error("API Error:", error.response.data);
            message = "Diagnosis service error";
        }
        res.status(500).json({ 
            success: false, 
            message 
        });
    }
});
// app.get("/test-home", (req, res) => {
//     res.render("Home", {
//         user: {
//             name: "Test User",
//             email: "test@example.com",
//             gender: "Male",
//             age: 30,
//             height: 175,
//             weight: 70,
//             activityLevel: "moderatelyActive"
//         },
//         bmi: "22.86",
//         calorieIntake: 2500
//     });
// });
// Add to your routes in index.js
// Enhanced AI Chat Endpoint
app.post('/api/chat', validateSession, async (req, res) => {
    try {
        const { message, userData } = req.body;
        
        // Enhanced response generation with context
        const response = generateAIResponse(message, userData);
        
        res.json({ 
            success: true, 
            response,
            suggestions: getFollowUpQuestions(message) 
        });
    } catch (error) {
        console.error('Chat error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Chat service unavailable' 
        });
    }
});

// Enhanced AI response generator
function generateAIResponse(message, userData = {}) {
    const lowerMsg = message.toLowerCase();
    
    // Health-related responses
    if (/(headache|pain|hurt|ache)/i.test(lowerMsg)) {
        return `Based on your symptoms, you might consider:
- Resting in a quiet room
- Drinking water (${userData.waterIntake || '2'}L recommended daily)
- Over-the-counter options: ${OTC_MEDICINES.headache.map(m => m.name).join(', ')}`;
    }
    else if (/(bmi|weight|fat)/i.test(lowerMsg)) {
        const bmi = (userData.weight / ((userData.height/100) ** 2)).toFixed(2);
        return `Your BMI is approximately ${bmi}. ${getBMICategory(bmi)}`;
    }
    else if (/(calori|diet|eat|food)/i.test(lowerMsg)) {
        return `Based on your profile (${userData.activityLevel || 'moderate'} activity), your daily calorie needs are about ${userData.calorieIntake || 2000} kcal.`;
    }
    else if (/(hello|hi|hey)/i.test(lowerMsg)) {
        return "Hello there! I'm your Medico health assistant. I can help with:\n- Symptom analysis\n- Medication information\n- Health tracking\nWhat would you like to discuss today?";
    }
    else if (/(thank|thanks|appreciate)/i.test(lowerMsg)) {
        return "You're welcome! Is there anything else I can help you with regarding your health?";
    }
    
    // Default intelligent responses
    return getContextualResponse(lowerMsg, userData);
}

function getBMICategory(bmi) {
    if (bmi < 18.5) return "This suggests you might be underweight. Consider consulting a nutritionist.";
    if (bmi < 25) return "This is in the healthy range. Good job maintaining your weight!";
    if (bmi < 30) return "This suggests you might be overweight. Regular exercise can help.";
    return "This suggests obesity. You might want to consult a healthcare provider.";
}

function getContextualResponse(message, userData) {
    const responses = [
        "I understand you're asking about health. Could you tell me more about your specific concern?",
        `Based on your profile (${userData.age || 'unknown'} years, ${userData.gender || 'unknown'}), I'd recommend discussing this with your doctor for personalized advice.`,
        "That's an interesting health question. Would you like me to check your symptoms or provide general information?",
        "I can help with medication information, symptom analysis, or general health advice. What specifically would you like to know?"
    ];
    return responses[Math.floor(Math.random() * responses.length)];
}

function getFollowUpQuestions(message) {
    const lowerMsg = message.toLowerCase();
    
    if (/(headache|pain)/i.test(lowerMsg)) {
        return [
            "How long have you had this pain?",
            "Is the pain severe or mild?",
            "Have you taken any medication?"
        ];
    }
    if (/(diet|food|eat)/i.test(lowerMsg)) {
        return [
            "Would you like meal suggestions?",
            "Are you following any specific diet?",
            "Do you have any food allergies?"
        ];
    }
    
    return [
        "Would you like more detailed information?",
        "Should I check your symptoms related to this?",
        "Would you like me to save this concern to your health log?"
    ];
}
// Home Route
app.get("/home", validateSession, async (req, res) => {
    try {
        // 1. Get the user with ALL required fields
        const user = await User.findById(req.user._id).lean();
        
        if (!user) {
            console.error("USER NOT FOUND IN DB");
            return res.redirect("/logout");
        }
        const safeUser = {
            name: user?.name || "User",
            email: user?.email || "",
            gender: user?.gender || "Other",
            age: user?.age || 25,
            height: user?.height || 170,
            weight: user?.weight || 70,
            activityLevel: user?.activityLevel || "sedentary"
        };

        const heightInMeters = safeUser.height / 100;
        const bmi = (safeUser.weight / (heightInMeters * heightInMeters)).toFixed(2);

        const bmr = safeUser.gender === "Male" 
            ? 10 * safeUser.weight + 6.25 * safeUser.height - 5 * safeUser.age + 5
            : 10 * safeUser.weight + 6.25 * safeUser.height - 5 * safeUser.age - 161;
        
        const activityMultipliers = {
            sedentary: 1.2,
            lightlyActive: 1.375,
            moderatelyActive: 1.55,
            veryActive: 1.725,
            extraActive: 1.9
        };
        
        const calorieIntake = Math.round(bmr * (activityMultipliers[safeUser.activityLevel] || 1.2));

        const renderData = {
            user: safeUser,
            bmi: bmi,
            calorieIntake: calorieIntake
        };

        console.log("RENDERING WITH DATA:", JSON.stringify(renderData, null, 2));

        return res.render("Home", renderData);

    } catch (error) {
        console.error("FATAL HOME ROUTE ERROR:", error);
        // Emergency fallback render
        return res.render("Home", {
            user: {
                name: "User",
                email: "",
                gender: "Other",
                age: 25,
                height: 170,
                weight: 70,
                activityLevel: "sedentary"
            },
            bmi: "22.0",
            calorieIntake: 2000
        });
    }
});
app.get("/home-debug", validateSession, async (req, res) => {
    try {
        const user = req.user;
        console.log("USER OBJECT FROM DB:", user);
        
        // Force-calculate with test values to isolate the issue
        const testBMI = (70 / ((1.75) ** 2)).toFixed(2);
        const testCalories = 2500;
        
        res.render("Home", {
            user: {
                name: "DEBUG USER",
                email: "debug@test.com",
                gender: "Male",
                age: 30,
                height: 175,
                weight: 70,
                activityLevel: "moderatelyActive"
            },
            bmi: testBMI,
            calorieIntake: testCalories
        });
    } catch (error) {
        console.error("DEBUG ROUTE ERROR:", error);
        res.status(500).send("Debug error");
    }
});
app.get("/dbinfo", async (req, res) => {
    try {
        const db = mongoose.connection.db;
        const info = {
            database: db.databaseName,
            collections: await db.listCollections().toArray(),
            userCount: await User.countDocuments(),
            sampleUser: await User.findOne()
        };
        res.json(info);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Signup Route (OTP Generation)
app.post("/signup", async (req, res) => {
    try {
        const { uname, email, password } = req.body;

        // Basic validation
        if (!uname || !email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: "All fields are required" 
            });
        }

        // Password strength validation (client-side should match this)
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({
                success: false,
                message: "Password must contain:\n" +
                         "- Minimum 8 characters\n" +
                         "- At least 1 uppercase letter\n" +
                         "- At least 1 lowercase letter\n" +
                         "- At least 1 number\n" +
                         "- At least 1 special character (@$!%*?&)"
            });
        }
        // Check if the email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: "Email already exists." });
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = otp;
        setTimeout(() => delete otpStore[email], 5 * 60 * 1000);

        // Send OTP via email
        await transporter.sendMail({
            from: "Medico App <your-email@gmail.com>",
            to: email,
            subject: "Your OTP for Signup",
            text: `Your OTP for signup is: ${otp}`,
        });

        console.log(`✅ OTP for ${email}: ${otp}`);
        res.json({ success: true, message: "OTP sent", email });
    } catch (error) {
        console.error("❌ Error during signup:", error);
        res.status(500).json({ success: false, message: "Server error. Please try again." });
    }
});

// Enhanced OTP verification with better logging
app.post("/verify-otp", async (req, res) => {
    try {
        const { email, otp, password, uname } = req.body;

        // Verify OTP
        if (!otpStore[email] || otpStore[email].toString() !== otp.trim()) {
            return res.status(400).json({ success: false, message: "Invalid OTP." });
        }

        // Create a new user with better logging
        console.log(`Creating user: ${email}`);
        const newUser = new User({
            name: uname,
            email: email,
            password: password,
        });

        const savedUser = await newUser.save();
        console.log('User created successfully:', savedUser);
        delete otpStore[email];

        // Create new session
        req.session.regenerate((err) => {
            if (err) {
                console.error("Session regeneration error:", err);
                return res.status(500).json({ 
                    success: false, 
                    message: "Account created but login failed. Please try logging in." 
                });
            }
            
            req.session.user = { 
                uname: newUser.name, 
                email: newUser.email,
                userId: newUser._id
            };
            
            res.json({ 
                success: true, 
                redirectUrl: "/basic-info", 
                email 
            });
        });
    } catch (error) {
        console.error("❌ Error during OTP verification:", error);
        if (error.code === 11000) {
            return res.status(400).json({ success: false, message: "Email already exists." });
        }
        res.status(500).json({ success: false, message: "Server error. Please try again." });
    }
});


// Basic Info Submission Route
app.post("/basic-info", validateSession, async (req, res) => {
    try {
        const { gender, age, height, weight, activityLevel } = req.body;

        const updatedUser = await User.findOneAndUpdate(
            { email: req.session.user.email },
            { gender, age, height, weight, activityLevel },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        res.json({ success: true, redirectUrl: "/home" });
    } catch (error) {
        console.error("❌ Error updating basic info:", error);
        res.status(500).json({ success: false, message: "Server error. Please try again." });
    }
});

// Login Route
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const trimmedPassword = password.trim();

        if (!email || !trimmedPassword) {
            return res.status(400).json({ 
                success: false, 
                message: "Email and password are required." 
            });
        }

        const user = await User.findOne({ email }).select('+password');
        if (!user) {
            req.session.destroy();
            return res.status(400).json({ 
                success: false, 
                message: "Invalid credentials." 
            });
        }

        const isPasswordValid = await user.comparePassword(trimmedPassword);
        if (!isPasswordValid) {
            return res.status(400).json({ 
                success: false, 
                message: "Invalid credentials." 
            });
        }

        // Create new session
        req.session.regenerate((err) => {
            if (err) {
                console.error("Session regeneration error:", err);
                return res.status(500).json({ 
                    success: false, 
                    message: "Login failed. Please try again." 
                });
            }
            
            req.session.user = { 
                uname: user.name, 
                email: user.email,
                userId: user._id
            };
            
            res.json({ 
                success: true, 
                message: "Login successful", 
                redirectUrl: "/home" 
            });
        });
    } catch (error) {
        console.error("❌ Login error:", error);
        res.status(500).json({ 
            success: false, 
            message: "Server error. Try again later." 
        });
    }
});

// Settings Route
app.get("/settings", validateSession, async (req, res) => {
    try {
        res.render("settings", {
            currentPage: 'settings',
            uname: req.user.name,
            email: req.user.email,
            activityLevel: req.user.activityLevel || "sedentary",
        });
    } catch (error) {
        console.error("❌ Error fetching user data:", error);
        res.status(500).send("Error fetching user data.");
    }
});

// Update Password Route
app.post("/update-password", validateSession, async (req, res) => {
    try {
        const { currentPassword, newPassword, confirmPassword, logoutAll } = req.body;

        if (!currentPassword || !newPassword || !confirmPassword) {
            return res.status(400).json({ success: false, message: "All fields are required" });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ success: false, message: "New passwords do not match" });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ 
                success: false, 
                message: "Password must be at least 6 characters long" 
            });
        }

        const user = req.user;

        const isPasswordValid = await user.comparePassword(currentPassword);
        if (!isPasswordValid) {
            return res.status(400).json({ 
                success: false, 
                message: "Current password is incorrect" 
            });
        }

        // Update password (pre-save hook will hash it)
        user.password = newPassword;
        await user.save();

        const response = { 
            success: true, 
            message: "Password updated successfully" 
        };

        if (logoutAll) {
            req.session.destroy();
            response.logout = true;
        }

        res.json(response);
    } catch (error) {
        console.error("❌ Error updating password:", error);
        res.status(500).json({ 
            success: false, 
            message: "An unexpected error occurred. Please try again later." 
        });
    }
});

// Delete Account Route
app.post("/delete-account", validateSession, async (req, res) => {
    try {
        const { currentPassword } = req.body;

        if (!currentPassword) {
            return res.status(400).json({ 
                success: false, 
                message: "Password is required" 
            });
        }

        const user = req.user;

        const isPasswordValid = await user.comparePassword(currentPassword);
        if (!isPasswordValid) {
            return res.status(400).json({ 
                success: false, 
                message: "Password is incorrect" 
            });
        }

        // Delete the user with confirmation
        const result = await User.deleteOne({ _id: user._id });
        console.log('Delete operation result:', result);
        
        if (result.deletedCount === 0) {
            return res.status(404).json({ 
                success: false, 
                message: "User not found" 
            });
        }

        // Destroy session
        req.session.destroy((err) => {
            if (err) {
                console.error("❌ Error destroying session:", err);
                return res.status(500).json({ 
                    success: false, 
                    message: "Error during logout" 
                });
            }
            res.clearCookie('connect.sid', { path: '/' });
            
            res.json({ 
                success: true, 
                message: "Account deleted successfully",
                redirectUrl: "/"
            });
        });
    } catch (error) {
        console.error("❌ Error deleting account:", error);
        res.status(500).json({ 
            success: false, 
            message: "An unexpected error occurred. Please try again later." 
        });
    }
});

// Health Stats Route
app.get("/health-stats", validateSession, async (req, res) => {
    try {
        const user = req.user;

        // Calculate BMI
        const bmi = (user.weight / ((user.height / 100) ** 2)).toFixed(2);

        // Calculate BMR
        let bmr;
        if (user.gender === "Male") {
            bmr = 10 * user.weight + 6.25 * user.height - 5 * user.age + 5;
        } else if (user.gender === "Female") {
            bmr = 10 * user.weight + 6.25 * user.height - 5 * user.age - 161;
        } else {
            const maleBMR = 10 * user.weight + 6.25 * user.height - 5 * user.age + 5;
            const femaleBMR = 10 * user.weight + 6.25 * user.height - 5 * user.age - 161;
            bmr = (maleBMR + femaleBMR) / 2;
        }

        // Activity level multipliers
        const activityLevels = {
            sedentary: 1.2,
            lightlyActive: 1.375,
            moderatelyActive: 1.55,
            veryActive: 1.725,
            extraActive: 1.9
        };

        const calorieIntake = Math.round(bmr * activityLevels[user.activityLevel]);

        res.render("health-stats", {
            currentPage: 'health-stats',
            bmi: bmi,
            calorieIntake: calorieIntake,
        });
    } catch (error) {
        console.error("❌ Error fetching health stats:", error);
        res.status(500).send("Error fetching health stats.");
    }
});

// Profile Route
app.get("/profile", validateSession, async (req, res) => {
    try {
        const user = req.user;
        res.render("profile", {
            currentPage: 'profile', 
            uname: user.name,
            email: user.email,
            gender: user.gender,
            age: user.age,
            height: user.height,
            weight: user.weight,
            activityLevel: user.activityLevel || "sedentary",
        });
    } catch (error) {
        console.error("❌ Error fetching user data:", error);
        res.status(500).send("Error fetching user data.");
    }
});

// Update Profile Route
app.post("/update-profile", validateSession, async (req, res) => {
    try {
        const { name, email, gender, age, height, weight, activityLevel } = req.body;

        const updatedUser = await User.findOneAndUpdate(
            { _id: req.user._id },
            { name, email, gender, age, height, weight, activityLevel },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        // Update session data
        req.session.user.uname = updatedUser.name;
        req.session.user.email = updatedUser.email;

        res.json({ 
            success: true, 
            message: "Profile updated successfully!",
            user: updatedUser
        });
    } catch (error) {
        console.error("❌ Error updating profile:", error);
        res.status(500).json({ 
            success: false, 
            message: "Server error. Please try again." 
        });
    }
});

// Logout Route
app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ success: false, message: "Logout failed" });
        }
        res.clearCookie('connect.sid', { path: '/' });
        res.json({ success: true, message: "Logged out successfully", redirectUrl: "/" });
    });
});

// About Page Route
app.get("/about", (req, res) => {
    res.render("about", {
        currentPage: 'about',
        title: "About Medico",
        developers: [
            { name: "Ayuj Singh", role: "Backend Developer" },
            { name: "Anushka Khare", role: "Frontend Developer" }
        ],
        appInfo: {
            name: "Medico",
            version: "1.0.0",
            description: "Your personal health companion app"
        },
        user: req.session.user || null
    });
});

// Contact Page Route
app.get("/contact", (req, res) => {
    res.render("contact", {
        currentPage: 'contact',
        title: "Contact Us",
        contactInfo: {
            email: "support@medico.com",
            phone: "+1 (555) 123-4567",
            address: "123 Health Street, Wellness City"
        },
        user: req.session.user || null
    });
});

// Contact Form Submission
app.post("/contact", async (req, res) => {
    try {
        const { name, email, message } = req.body;
        
        await transporter.sendMail({
            from: `"Medico Contact Form" <${process.env.EMAIL_USER}>`,
            to: process.env.ADMIN_EMAIL || "admin@medico.com",
            subject: `New Contact Message from ${name}`,
            text: `Name: ${name}\nEmail: ${email}\nMessage: ${message}`
        });

        await transporter.sendMail({
            from: `"Medico App" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: "We received your message!",
            text: `Thank you for contacting us, ${name}!\n\nWe'll get back to you soon regarding your message:\n\n"${message}"`
        });

        res.json({ success: true, message: "Thank you! Your message has been sent." });
    } catch (error) {
        console.error("Contact form error:", error);
        res.status(500).json({ success: false, message: "Failed to send message. Please try again later." });
    }
});
app.get("/symptom-checker", validateSession, (req, res) => {
    res.render("symptom-checker", {
        currentPage: 'symptom-checker',
        uname: req.user.name,
        email: req.user.email,
        gender: req.user.gender,
        age: req.user.age
    });
});
// Session Cleanup Job (runs every hour)
setInterval(async () => {
    try {
        const sessions = await mongoose.connection.db.collection('sessions').find().toArray();
        
        for (const session of sessions) {
            try {
                const sessionData = JSON.parse(session.session);
                if (sessionData.user && sessionData.user.email) {
                    const user = await User.findOne({ email: sessionData.user.email });
                    if (!user) {
                        await mongoose.connection.db.collection('sessions')
                            .deleteOne({ _id: session._id });
                    }
                }
            } catch (e) {
                console.error("Error processing session:", e);
            }
        }
    } catch (error) {
        console.error("Session cleanup error:", error);
    }
}, 60 * 60 * 1000); // Every hour

// Start Server
const port = process.env.PORT || 5001;
app.listen(port, () => console.log(`🚀 Server running on Port: ${port}`));
