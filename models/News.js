// FILE: models/News.js
import mongoose from "mongoose";
import slugify from "slugify";

// lightweight slug generator (no external deps)
const makeSlug = (s) =>
    String(s || "")
        .toLowerCase()
        .normalize("NFKD")
        .replace(/[\u0300-\u036f]/g, "")     // strip accents
        .replace(/[^a-z0-9]+/g, "-")         // non-alnum -> hyphen
        .replace(/^-+|-+$/g, "")             // trim hyphens
        .slice(0, 80);

const NewsSchema = new mongoose.Schema(
    {
        title: { type: String, required: true, trim: true, maxlength: 180 },
        slug: { type: String, required: true, unique: true, index: true },
        blurb: { type: String, default: "", maxlength: 300 },
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

NewsSchema.statics.ensureUniqueSlug = async function (base, selfId) {
    let s = makeSlug(base);
    if (!s) s = "post";
    let i = 1;
    while (await this.exists({ slug: s, _id: { $ne: selfId } })) {
        i += 1;
        s = `${makeSlug(base)}-${i}`;
    }
    return s;
};

NewsSchema.pre("validate", async function () {
    if (!this.slug && this.title) {
        this.slug = await this.constructor.ensureUniqueSlug(this.title, this._id);
    }
});










export default mongoose.models.News || mongoose.model("News", NewsSchema);
