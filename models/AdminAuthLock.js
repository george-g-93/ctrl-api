// models/AdminAuthLock.js
import mongoose from "mongoose";

const AdminAuthLockSchema = new mongoose.Schema({
  // Track by email (you could also add IP dimension if you like)
  email: { type: String, unique: true, index: true },
  failedCount: { type: Number, default: 0 },
  lastFailedAt: { type: Date },
  lockUntil: { type: Date, default: null }, // if in future -> locked
}, { versionKey: false });

export default mongoose.model("AdminAuthLock", AdminAuthLockSchema);
