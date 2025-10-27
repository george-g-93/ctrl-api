// models/AdminAuthLog.js
import mongoose from "mongoose";

const AdminAuthLogSchema = new mongoose.Schema({
  email: { type: String, index: true },
  ip: String,
  ua: String,
  success: { type: Boolean, index: true },
  reason: { type: String, default: "" }, // e.g. "invalid_password", "user_not_found", "locked"
  createdAt: { type: Date, default: Date.now, index: true },
}, { versionKey: false });

export default mongoose.model("AdminAuthLog", AdminAuthLogSchema);
