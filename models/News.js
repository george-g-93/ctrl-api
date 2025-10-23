// FILE: models/News.js
import mongoose from "mongoose";
import slugify from "slugify";

const NewsSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true, maxlength: 180 },
    slug: { type: String, required: true, unique: true, index: true },
    blurb: { type: String, default: "" , maxlength: 300 },
    content: { type: String, default: "" },            // HTML or Markdown
    coverUrl: { type: String, default: "" },
    tags: [{ type: String, trim: true }],
    status: { type: String, enum: ["draft", "published"], default: "draft", index: true },
    publishedAt: { type: Date, default: null, index: true },
    deletedAt: { type: Date, default: null, index: true },
    author: { type: String, default: "CTRL" },
  },
  { timestamps: true }
);

// auto-generate slug on create or when title changes (if no slug provided)
NewsSchema.pre("validate", function (next) {
  if (!this.slug && this.title) {
    this.slug = slugify(this.title, { lower: true, strict: true });
  }
  next();
});

export default mongoose.models.News || mongoose.model("News", NewsSchema);
