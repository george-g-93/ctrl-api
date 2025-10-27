// models/Blog.js
import mongoose from "mongoose";

const BlogSchema = new mongoose.Schema({
  title: { type: String, required: true },
  slug:  { type: String, required: true, unique: true, index: true },
  date:  { type: Date, default: Date.now, index: true },
  blurb: { type: String, default: "" },
  content: { type: String, default: "" },     // markdown or HTML
  published: { type: Boolean, default: true, index: true },
  author: { type: String, default: "" },
  tags: { type: [String], default: [], index: true },
  heroUrl: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date },
  deletedAt: { type: Date, default: null, index: true },
}, { versionKey: false });

BlogSchema.pre("save", function(next) {
  this.updatedAt = new Date();
  next();
});

export default mongoose.model("Blog", BlogSchema);
