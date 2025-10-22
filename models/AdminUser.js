import mongoose from "mongoose";

const AdminUserSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, required: true, index: true },
    mfaSecret: { type: String, default: "" }, // base32 secret
  },
  { timestamps: true }
);

export default mongoose.model("AdminUser", AdminUserSchema);
