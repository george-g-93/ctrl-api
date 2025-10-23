// models/News.js
import mongoose from "mongoose";

const NewsSchema = new mongoose.Schema({
  title:   { type: String, required: true },
  slug:    { type: String, required: true, unique: true, index: true },
  date:    { type: Date,   required: true },
  blurb:   { type: String, default: "" },
  content: { type: String, default: "" }, // store HTML or markdown
  published: { type: Boolean, default: true },
}, { timestamps: true });

export default mongoose.model("News", NewsSchema);