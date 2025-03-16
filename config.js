const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

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

module.exports = { User };