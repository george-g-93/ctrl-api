// /opt/ctrl-api/models/ContactMessage.js
import mongoose from "mongoose";

const ContactMessageSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    company: { type: String, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true },
    fleetSize: { type: String, trim: true },
    message: { type: String, required: true, trim: true },
    // spam honeypot (should stay empty):
    website: { type: String, default: "" },
    ip: String,
    ua: String,
  },
  { timestamps: true }
);

export default mongoose.model("ContactMessage", ContactMessageSchema);
