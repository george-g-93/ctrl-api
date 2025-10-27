// models/BlogComment.js
import mongoose from "mongoose";

const BlogCommentSchema = new mongoose.Schema({
  blogId: { type: mongoose.Schema.Types.ObjectId, ref: "Blog", index: true },
  slug:   { type: String, index: true },            // store slug for convenience
  name:   { type: String, required: true },
  email:  { type: String, default: "" },            // optional, not public
  body:   { type: String, required: true },         // plain text only
  approved: { type: Boolean, default: false, index: true },
  ip:     { type: String, default: "" },
  ua:     { type: String, default: "" },
  createdAt: { type: Date, default: Date.now, index: true },
  deletedAt: { type: Date, default: null, index: true },
}, { versionKey: false });

export default mongoose.model("BlogComment", BlogCommentSchema);
