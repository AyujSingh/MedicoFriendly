const express = require("express");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const dotenv = require("dotenv");
const session = require("express-session");
const mongoose = require("mongoose");

dotenv.config();
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(express.static("public"));

// Session Middleware
app.use(
    session({
        secret: process.env.SESSION_SECRET || "yourSecretKey",
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false, maxAge: 1000 * 60 * 60 * 24 }, // 1 day
    })
);

// Connect to MongoDB
async function connectDB() {
    try {
        console.log("🚀 Attempting to connect to MongoDB...");
        const uri = process.env.MONGO_URI || "mongodb://localhost:27017/Users";
        console.log("🔗 Using MONGO_URI:", uri);

        await mongoose.connect(uri, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 30000, // 30 seconds timeout
            socketTimeoutMS: 45000, // Increase socket timeout
            connectTimeoutMS: 30000, // Increase connection timeout
        });

        console.log("✅ Database connected successfully");
    } catch (error) {
        console.error("❌ Database connection failed:", error.message);
        process.exit(1); // Exit process if DB connection fails
    }
}
connectDB();

// User Schema
const UserSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: [true, "Name is required"],
            trim: true
        },
        email: {
            type: String,
            required: [true, "Email is required"],
            unique: true,
            trim: true,
            lowercase: true,
            match: [/^\S+@\S+\.\S+$/, "Please use a valid email address"], // Email validation
        },
        password: {
            type: String,
            required: [true, "Password is required"],
            minlength: [6, "Password must be at least 6 characters long"]
        },
        gender: {
            type: String,
            enum: ["Male", "Female", "Other"],
            default: "Other"
        },
        age: {
            type: Number,
            min: [1, "Age must be at least 1"],
        },
        height: {
            type: Number,
            min: [30, "Height must be at least 30 cm"],
        },
        weight: {
            type: Number,
            min: [1, "Weight must be at least 1 kg"],
        },
    },
    { timestamps: true }
);

// Pre-save hook to hash the password before saving
UserSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next(); // Skip if password is not modified

    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        console.log("✅ Password hashed successfully.");
        next();
    } catch (error) {
        console.error("❌ Error hashing password:", error.message);
        next(error);
    }
});

// Method to compare passwords
UserSchema.methods.comparePassword = async function (candidatePassword) {
    try {
        console.log("🔑 Comparing passwords...");
        console.log("🔑 Candidate password:", candidatePassword);
        console.log("🔑 Stored hash:", this.password);

        // Trim the candidate password to remove any extra whitespace
        const trimmedPassword = candidatePassword.trim();

        // Compare the trimmed password with the stored hash
        const isMatch = await bcrypt.compare(trimmedPassword, this.password);
        console.log("🔑 Password match result:", isMatch);
        return isMatch;
    } catch (error) {
        console.error("❌ Error comparing password:", error.message);
        return false;
    }
};

// User Model
const User = mongoose.model("User", UserSchema);

const otpStore = {};

// Nodemailer Setup
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Routes
app.get("/", (req, res) => res.render("Login"));
app.get("/signup", (req, res) => res.render("Signup"));
app.get("/basic-info", (req, res) => {
    if (!req.session.user) return res.redirect("/");
    res.render("BasicForm");
});

// Home Route
app.get("/home", async (req, res) => {
    if (!req.session.user) return res.redirect("/");

    try {
        // Fetch user data from the database
        const user = await User.findOne({ email: req.session.user.email });

        if (!user) {
            return res.status(404).send("User not found.");
        }

        // Calculate BMI
        const bmi = (user.weight / ((user.height / 100) ** 2)).toFixed(2);

        // Calculate Basal Metabolic Rate (BMR) using Mifflin-St Jeor Equation
        let bmr;
        if (user.gender === "Male") {
            bmr = 10 * user.weight + 6.25 * user.height - 5 * user.age + 5;
        } else if (user.gender === "Female") {
            bmr = 10 * user.weight + 6.25 * user.height - 5 * user.age - 161;
        } else {
            // For "Other" gender, use an average of male and female BMR
            const maleBMR = 10 * user.weight + 6.25 * user.height - 5 * user.age + 5;
            const femaleBMR = 10 * user.weight + 6.25 * user.height - 5 * user.age - 161;
            bmr = (maleBMR + femaleBMR) / 2;
        }

        // Adjust BMR based on activity level
        const activityLevels = {
            sedentary: 1.2,       // Little or no exercise
            lightlyActive: 1.375, // Light exercise/sports 1-3 days/week
            moderatelyActive: 1.55, // Moderate exercise/sports 3-5 days/week
            veryActive: 1.725,    // Hard exercise/sports 6-7 days/week
            extraActive: 1.9      // Very hard exercise/sports & physical job
        };

        const activityLevel = user.activityLevel || "sedentary"; // Default to sedentary
        const calorieIntake = Math.round(bmr * activityLevels[activityLevel]);

        // Render the home page with user data
        res.render("Home", {
            uname: user.name,
            email: user.email,
            gender: user.gender,
            age: user.age,
            height: user.height,
            weight: user.weight,
            bmi: bmi,
            calorieIntake: calorieIntake,
        });
    } catch (error) {
        console.error("❌ Error fetching user data:", error);
        res.status(500).send("Error fetching user data.");
    }
});

// Signup Route (OTP Generation)
app.post("/signup", async (req, res) => {
    try {
        const { uname, email, password } = req.body;

        // Check if the email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: "Email already exists." });
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = otp;
        setTimeout(() => delete otpStore[email], 5 * 60 * 1000); // OTP expires after 5 minutes

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

// OTP Verification & Account Creation
app.post("/verify-otp", async (req, res) => {
    try {
        const { email, otp, password, uname } = req.body;

        // Verify OTP
        if (!otpStore[email] || otpStore[email].toString() !== otp.trim()) {
            return res.status(400).json({ success: false, message: "Invalid OTP." });
        }

        // Create a new user (password will be hashed by the pre-save hook)
        const newUser = new User({
            name: uname,
            email: email,
            password: password, // Password will be hashed before saving
        });

        // Save the user to the database
        await newUser.save();

        // Delete the OTP from the store
        delete otpStore[email];

        // Save user session
        req.session.user = { uname, email };

        // Respond with success
        res.json({ success: true, redirectUrl: "/basic-info", email });
    } catch (error) {
        console.error("❌ Error during OTP verification:", error);

        // Handle duplicate email error
        if (error.code === 11000) {
            return res.status(400).json({ success: false, message: "Email already exists." });
        }

        res.status(500).json({ success: false, message: "Server error. Please try again." });
    }
});

// Basic Info Submission Route
app.post("/basic-info", async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Unauthorized access" });
    }

    try {
        const { gender, age, height, weight, activityLevel } = req.body;

        // Find the user by email and update their basic info
        const updatedUser = await User.findOneAndUpdate(
            { email: req.session.user.email }, // Find by email
            { gender, age, height, weight, activityLevel }, // Update fields
            { new: true } // Return the updated document
        );

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        console.log(`✅ User ${req.session.user.uname} submitted basic info`);
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

        // Trim the password to remove any extra whitespace
        const trimmedPassword = password.trim();

        // Debug: Log the email being used for login
        console.log("Login attempt with email:", email);

        // Find the user by email
        console.log("Attempting to find user in the database...");
        const user = await User.findOne({ email });
        if (!user) {
            console.log("User not found for email:", email);
            return res.status(400).json({ success: false, message: "User not found." });
        }

        // Debug: Log the user found
        console.log("User found:", user);

        // Debug: Log the entered password and stored hash
        console.log("Entered password:", trimmedPassword);
        console.log("Stored hash:", user.password);

        // Verify the password using the comparePassword method
        console.log("Attempting to compare passwords...");
        const isPasswordValid = await user.comparePassword(trimmedPassword);
        console.log("Password match result:", isPasswordValid);

        if (!isPasswordValid) {
            console.log("Invalid password for email:", email);
            return res.status(400).json({ success: false, message: "Invalid password." });
        }

        // Debug: Log successful login
        console.log("Login successful for email:", email);

        // Save user session
        req.session.user = { uname: user.name, email: user.email };

        // Respond with success
        res.json({ success: true, message: "Login successful", redirectUrl: "/home" });
    } catch (error) {
        console.error("❌ Login error:", error);
        res.status(500).json({ success: false, message: "Server error. Try again later." });
    }
});
// Settings Route
app.get("/settings", async (req, res) => {
    if (!req.session.user) return res.redirect("/"); // Ensure user is logged in

    try {
        // Fetch user data from the database
        const user = await User.findOne({ email: req.session.user.email });

        if (!user) {
            return res.status(404).send("User not found.");
        }

        // Render the settings page with user data
        res.render("settings", {
            uname: user.name,
            email: user.email,
            activityLevel: user.activityLevel || "sedentary", // Default to sedentary
        });
    } catch (error) {
        console.error("❌ Error fetching user data:", error);
        res.status(500).send("Error fetching user data.");
    }
});
// Health Stats Route
app.get("/health-stats", async (req, res) => {
    if (!req.session.user) return res.redirect("/"); // Ensure user is logged in

    try {
        // Fetch user data from the database
        const user = await User.findOne({ email: req.session.user.email });

        if (!user) {
            return res.status(404).send("User not found.");
        }

        // Calculate BMI
        const bmi = (user.weight / ((user.height / 100) ** 2)).toFixed(2);

        // Calculate Basal Metabolic Rate (BMR) using Mifflin-St Jeor Equation
        let bmr;
        if (user.gender === "Male") {
            bmr = 10 * user.weight + 6.25 * user.height - 5 * user.age + 5;
        } else if (user.gender === "Female") {
            bmr = 10 * user.weight + 6.25 * user.height - 5 * user.age - 161;
        } else {
            // For "Other" gender, use an average of male and female BMR
            const maleBMR = 10 * user.weight + 6.25 * user.height - 5 * user.age + 5;
            const femaleBMR = 10 * user.weight + 6.25 * user.height - 5 * user.age - 161;
            bmr = (maleBMR + femaleBMR) / 2;
        }

        // Adjust BMR based on activity level
        const activityLevels = {
            sedentary: 1.2,       // Little or no exercise
            lightlyActive: 1.375, // Light exercise/sports 1-3 days/week
            moderatelyActive: 1.55, // Moderate exercise/sports 3-5 days/week
            veryActive: 1.725,    // Hard exercise/sports 6-7 days/week
            extraActive: 1.9      // Very hard exercise/sports & physical job
        };

        const activityLevel = user.activityLevel || "sedentary"; // Default to sedentary
        const calorieIntake = Math.round(bmr * activityLevels[activityLevel]);

        // Render the health stats page
        res.render("health-stats", {
            bmi: bmi,
            calorieIntake: calorieIntake,
        });
    } catch (error) {
        console.error("❌ Error fetching health stats:", error);
        res.status(500).send("Error fetching health stats.");
    }
});
// Profile Route
app.get("/profile", async (req, res) => {
    if (!req.session.user) return res.redirect("/"); // Ensure user is logged in

    try {
        // Fetch user data from the database
        const user = await User.findOne({ email: req.session.user.email });

        if (!user) {
            return res.status(404).send("User not found.");
        }

        // Render the profile page with user data
        res.render("profile", {
            uname: user.name,
            email: user.email,
            gender: user.gender,
            age: user.age,
            height: user.height,
            weight: user.weight,
            activityLevel: user.activityLevel || "sedentary", // Default to sedentary
        });
    } catch (error) {
        console.error("❌ Error fetching user data:", error);
        res.status(500).send("Error fetching user data.");
    }
});
/// Update Profile Route
app.post("/update-profile", async (req, res) => {
    if (!req.session.user) return res.redirect("/"); // Ensure user is logged in

    try {
        const { name, email, gender, age, height, weight, activityLevel } = req.body;

        // Find the user by email and update their profile
        const updatedUser = await User.findOneAndUpdate(
            { email: req.session.user.email }, // Find by email
            { name, email, gender, age, height, weight, activityLevel }, // Update fields
            { new: true } // Return the updated document
        );

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        // Update session data
        req.session.user.uname = updatedUser.name;

        // Respond with success
        res.json({ success: true, message: "Profile updated successfully!" });
    } catch (error) {
        console.error("❌ Error updating profile:", error);
        res.status(500).json({ success: false, message: "Server error. Please try again." });
    }
});
// Logout Route
app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ success: false, message: "Logout failed" });
        }
        res.json({ success: true, message: "Logged out successfully", redirectUrl: "/" });
    });
});

// Start Server
const port = process.env.PORT || 5001;
app.listen(port, () => console.log(`🚀 Server running on Port: ${port}`));