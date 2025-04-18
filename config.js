const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

// Enhanced User Schema with better validation
const UserSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: [true, "Name is required"],
            trim: true,
            minlength: [2, "Name must be at least 2 characters"]
        },
        email: {
            type: String,
            required: [true, "Email is required"],
            unique: true,
            trim: true,
            lowercase: true,
            validate: {
                validator: function(v) {
                    return /^\S+@\S+\.\S+$/.test(v);
                },
                message: props => `${props.value} is not a valid email address!`
            }
        },
        password: {
            type: String,
            required: [true, "Password is required"],
            validate: {
              validator: function(v) {
                return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(v);
              },
              message: props => `Password must contain:
              - At least 8 characters
              - At least 1 uppercase letter
              - At least 1 lowercase letter
              - At least 1 number
              - At least 1 special character (@$!%*?&)`
            },
            select: false
        },
        gender: {
            type: String,
            enum: {
                values: ["Male", "Female", "Other"],
                message: '{VALUE} is not a valid gender'
            },
            default: "Other"
        },
        age: {
            type: Number,
            min: [1, "Age must be at least 1"],
            max: [120, "Age must be less than 120"]
        },
        height: {
            type: Number,
            min: [30, "Height must be at least 30 cm"],
            max: [300, "Height must be less than 300 cm"]
        },
        weight: {
            type: Number,
            min: [1, "Weight must be at least 1 kg"],
            max: [500, "Weight must be less than 500 kg"]
        },
        activityLevel: {
            type: String,
            enum: ["sedentary", "lightlyActive", "moderatelyActive", "veryActive", "extraActive"],
            default: "sedentary"
        },
        lastPasswordChange: {
            type: Date,
            default: Date.now
        }
    },
    { 
        timestamps: true,
        toJSON: {
            virtuals: true,
            transform: function(doc, ret) {
                delete ret.password; // Never return password
                return ret;
            }
        },
        toObject: {
            virtuals: true,
            transform: function(doc, ret) {
                delete ret.password; // Never return password
                return ret;
            }
        }
    }
);

// Enhanced pre-save hook
UserSchema.pre("save", async function(next) {
    if (!this.isModified("password")) return next();

    try {
        console.log('Hashing password for user:', this.email);
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        this.lastPasswordChange = Date.now();
        console.log("✅ Password hashed successfully for:", this.email);
        next();
    } catch (error) {
        console.error("❌ Error hashing password for:", this.email, error);
        next(new Error("Failed to hash password"));
    }
});

// Enhanced password comparison method
UserSchema.methods.comparePassword = async function(candidatePassword) {
    try {
        if (!candidatePassword) {
            console.log('No password provided for comparison');
            return false;
        }

        const trimmedPassword = candidatePassword.trim();
        
        if (!this.password) {
            console.log('No hashed password stored for user');
            return false;
        }

        const isMatch = await bcrypt.compare(trimmedPassword, this.password);
        console.log(`Password comparison result for ${this.email}:`, isMatch);
        return isMatch;
    } catch (error) {
        console.error("❌ Error comparing password for:", this.email, error);
        return false;
    }
};

// Create index for better email query performance
UserSchema.index({ email: 1 }, { unique: true });

const User = mongoose.model("User", UserSchema);

module.exports = { User };
