import mongoose from "mongoose";

const ContactMessageSchema = new mongoose.Schema({
  name: { type: String, required: true },
  company: { type: String, default: "" },
  email: { type: String, required: true },
  fleetSize: { type: String, default: "" },
  message: { type: String, required: true },
  website: { type: String, default: "" }, // honeypot
  ip: { type: String, default: "" },
  ua: { type: String, default: "" },

  // 🔑 These two must be present so PATCH can set them
  read: { type: Boolean, default: false },
  deletedAt: { type: Date, default: null },
}, { timestamps: true });

export default mongoose.model("ContactMessage", ContactMessageSchema);
