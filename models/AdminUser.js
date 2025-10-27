// import mongoose from "mongoose";

// const AdminUserSchema = new mongoose.Schema(
//   {
//     email: { type: String, unique: true, required: true, index: true },
//     mfaSecret: { type: String, default: "" }, // base32 secret
//   },
//   { timestamps: true }
// );

// export default mongoose.model("AdminUser", AdminUserSchema);

// models/AdminUser.js
import mongoose from "mongoose";

const AdminUserSchema = new mongoose.Schema({
    email: { type: String, unique: true, index: true, required: true },
    passwordHash: { type: String, required: true },   // per-user password
    mfaSecret: { type: String, default: "" },          // per-user 2FA secret
    role: { type: String, enum: ["owner", "admin"], default: "admin" },
    createdAt: { type: Date, default: Date.now },
    lastLoginAt: { type: Date },
    trustedDevices: [{
        markerHash: String,
        expiresAt: Date,
    }],
});

export default mongoose.model("AdminUser", AdminUserSchema);
