import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import ContactMessage from "./models/ContactMessage.js"; // <-- ensure this file exists
import bcrypt from "bcryptjs";
import session from "cookie-session"; // package name: cookie-session
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import AdminUser from "./models/AdminUser.js";
import News from "./models/News.js";
import AdminAuthLog from "./models/AdminAuthLog.js";
import AdminAuthLock from "./models/AdminAuthLock.js";
import 'dotenv/config';
import Blog from "./models/Blogs.js";
import BlogComment from "./models/BlogComment.js";
import crypto from "crypto";





const app = express();

const IS_DEV = process.env.NODE_ENV !== "production";
app.set("trust proxy", 1);

const ALLOWED_ORIGINS = new Set([
  "https://ctrlcompliance.co.uk",
  "https://www.ctrlcompliance.co.uk",

  // dev ports
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:5180",        // 👈 add this
  "http://127.0.0.1:5180",        // 👈 and this
]);

const corsOptions = {
  origin(origin, cb) {
    // allow server-to-server / curl (no Origin header)
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.has(origin)) return cb(null, true);
    cb(new Error("CORS blocked: " + origin));
  },
  credentials: true,
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"],
};

app.use(cors(corsOptions));
// Make sure preflights succeed:
app.options(/.*/, cors(corsOptions));


// Body parsers etc.
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, _res, next) => {
  if (req.is('text/plain') && typeof req.body === 'string') {
    try { req.body = JSON.parse(req.body); } catch { /* leave as string */ }
  }
  next();
});


app.use(session({
  name: "sid",
  secret: process.env.SESSION_SECRET || "dev-secret",
  httpOnly: true,
  secure: IS_DEV ? false : true,                 // allow http on localhost
  sameSite: IS_DEV ? "lax" : "none",             // cross-site for prod, simpler in dev
  domain: IS_DEV ? undefined : ".ctrlcompliance.co.uk", // don't pin domain in dev
  maxAge: 1000 * 60 * 60 * 8,
}));

function getClientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (xf && typeof xf === "string") return xf.split(",")[0].trim();
  return req.ip;
}


// in-memory demo data; swap to DynamoDB later
// const news = [
//   {
//     id: "earned-recognition-pack",
//     date: "2025-10-10",
//     title: "CTRL launches Earned Recognition prep pack!",
//     blurb: "A practical set of templates and checks aligned to DVSA ER KPIs.",
//     content: "<p>We’ve released a practical pack…</p>"
//   },
//   {
//     id: "drivers-hours-pitfalls",
//     date: "2025-09-22",
//     title: "Webinar recap: Drivers’ hours pitfalls",
//     blurb: "Top 7 infringement patterns we keep seeing—and how to stop them."
//   }
// ];


async function isMfaEnrolled(email) {
  const u = await AdminUser.findOne({ email }).lean();
  return !!u?.mfaSecret;
}
function isMfaVerified(req) {
  return !!req.session?.mfaVerified; // session flag still per-login
}
async function getPersistedMfaSecret(email) {
  const u = await AdminUser.findOne({ email }).lean();
  return u?.mfaSecret || "";
}
async function setPersistedMfaSecret(email, secret) {
  await AdminUser.findOneAndUpdate(
    { email },
    { $set: { mfaSecret: secret } },
    { upsert: true }
  );
}

// --- Remembered device helpers ---
function hashDeviceMarker(marker) {
  return crypto.createHash("sha256").update(marker).digest("hex");
}

async function addTrustedDevice(email, marker) {
  const hashed = hashDeviceMarker(marker);
  const expiresAt = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000);
  await AdminUser.updateOne(
    { email },
    { $push: { trustedDevices: { markerHash: hashed, expiresAt } } },
    { upsert: false }
  );
}

async function isTrustedDevice(email, marker) {
  if (!marker) return false;
  const hashed = hashDeviceMarker(marker);
  const u = await AdminUser.findOne({ email }).lean();
  if (!u?.trustedDevices) return false;
  return u.trustedDevices.some(
    (d) => d.markerHash === hashed && d.expiresAt > new Date()
  );
}

// --- Connect to Mongo ---
const mongoUri = process.env.MONGODB_URI; // set in systemd env or .env
mongoose.set("strictQuery", true);
mongoose.connect(mongoUri, { dbName: "ctrl" })
  .then(() => console.log("Mongo connected"))
  .catch(err => { console.error("Mongo error", err); process.exit(1); });

// --- Rate limiting for /contact (per IP) ---
const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,     // 10 minutes
  max: 50,                      // generous; the real protection is the account lock
  standardHeaders: true,
  legacyHeaders: false,
});
app.post("/admin/login", loginLimiter); // attach before the route definition if using app-level middleware


// --- Validation schema ---
const ContactSchema = z.object({
  name: z.string().min(2),
  company: z.string().optional().default(""),
  email: z.string().email(),
  fleetSize: z.string().optional().default(""),
  message: z.string().min(5),
  website: z.string().optional().default(""), // honeypot
});



const NewsCreateSchema = z.object({
  title: z.string().min(3).max(180),
  blurb: z.string().max(300).optional().default(""),
  content: z.string().optional().default(""),
  coverUrl: z.string().url().optional().or(z.literal("")).default(""),
  tags: z.array(z.string().min(1).max(24)).optional().default([]),
  slug: z.string().min(3).max(200).optional().default(""),
  status: z.enum(["draft", "published"]).optional().default("draft"),
  publishedAt: z.string().datetime().optional().nullable(),
});

const NewsUpdateSchema = NewsCreateSchema.partial();

// --- Auth lockout policy ---
const AUTH_MAX_FAILED = parseInt(process.env.AUTH_MAX_FAILED ?? "5", 10);          // failures before lock
const AUTH_LOCK_MINUTES = parseInt(process.env.AUTH_LOCK_MINUTES ?? "30", 10);     // lock duration



// --- Validation schema ---
const NewUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(2).optional().default(""),
  password: z.string().min(8, "Minimum 8 characters"),
});

const UpdateUserSchema = z.object({
  name: z.string().min(2).optional(),
  disabled: z.boolean().optional(),
  password: z.string().min(8).optional(),
});


const MessageUpdateSchema = z.object({
  read: z.boolean(),
});


app.post("/contact", contactLimiter, async (req, res) => {
  try {
    // bot trap: if honeypot has content, ignore quietly
    if (typeof req.body.website === "string" && req.body.website.trim() !== "") {
      return res.status(204).end();
    }

    const data = ContactSchema.parse(req.body);

    const doc = await ContactMessage.create({
      ...data,
      ip: req.headers["x-forwarded-for"]?.toString().split(",")[0] ?? req.ip,
      ua: req.headers["user-agent"] ?? "",
    });

    return res.status(201).json({ ok: true, id: doc._id });
  } catch (err) {
    if (err?.issues) {
      return res.status(400).json({ ok: false, error: "Validation failed", details: err.issues });
    }
    console.error(err);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});



app.use((req, _res, next) => {
  if (req.path.startsWith('/admin')) {
    console.log('[ADMIN]', req.method, req.path, {
      hasSession: !!req.session,
      csrfCookie: req.session?.csrf,
      csrfHeader: req.get('X-CSRF-Token'),
      contentType: req.get('Content-Type'),
    });
  }
  next();
});

// issue a CSRF token for admin pages
app.get("/admin/csrf", (req, res) => {
  if (!req.session.csrf) req.session.csrf = Math.random().toString(36).slice(2);
  res.json({ csrf: req.session.csrf });
});
const requireCsrf = (req, res, next) => {
  // allow GET and CORS preflights to pass
  if (req.method === "GET" || req.method === "OPTIONS") return next();
  if (req.session?.csrf && req.get("X-CSRF-Token") === req.session.csrf) return next();
  return res.status(403).json({ ok: false, error: "CSRF" });
};

const requireAdmin = (req, res, next) => {
  if (req.method === "OPTIONS") return next();   // <-- allow preflight
  if (req.session?.admin === true) return next();
  return res.status(401).json({ ok: false, error: "Unauthorized" });
};

const requireAdminAndMfa = async (req, res, next) => {
  if (req.method === "OPTIONS") return next();   // <-- allow preflight
  if (req.path.startsWith("/admin/2fa/")) return next();
  if (!req.session?.admin) return res.status(401).json({ ok: false, error: "Unauthorized" });
  if (!(await isMfaEnrolled(req.session.email))) {
    return res.status(401).json({ ok: false, error: "MFA required (not enrolled)" });
  }
  if (!isMfaVerified(req)) {
    return res.status(401).json({ ok: false, error: "MFA required" });
  }
  next();
};


const requireMfa = (req, res, next) => {
  if (req.session?.mfaVerified === true) return next();
  return res.status(401).json({ ok: false, error: "MFA required" });
};


app.use("/admin/news", requireAdminAndMfa); // same as messages/users


// app.get("/news", (_req, res) => {
//   const sorted = [...news].sort((a, b) => new Date(b.date) - new Date(a.date));
//   res.json(sorted);
// });
// app.get("/news/:id", (req, res) => {
//   const item = news.find(n => n.id === req.params.id);
//   if (!item) return res.status(404).json({ error: "Not found" });
//   res.json(item);
// });


// GET public list (published only)
app.get("/news", async (req, res) => {
  const { page = "1", limit = "20" } = req.query;
  const p = Math.max(parseInt(page), 1);
  const l = Math.max(parseInt(limit), 1);

  const where = { status: "published", deletedAt: null };
  const [items, total] = await Promise.all([
    News.find(where).sort({ publishedAt: -1, createdAt: -1 }).skip((p - 1) * l).limit(l).lean(),
    News.countDocuments(where),
  ]);

  // keep a simple shape for the site
  const out = items.map(n => ({
    _id: n._id,
    title: n.title,
    slug: n.slug,
    blurb: n.blurb,
    date: n.publishedAt || n.createdAt,
  }));

  res.json({ items: out, total });
});

// GET public single by slug
app.get("/news/:slug", async (req, res) => {
  const item = await News.findOne({
    slug: req.params.slug,
    status: "published",
    deletedAt: null,
  }).lean();
  if (!item) return res.status(404).json({ error: "Not found" });

  res.json({
    _id: item._id,
    title: item.title,
    slug: item.slug,
    blurb: item.blurb,
    content: item.content,
    coverUrl: item.coverUrl,
    date: item.publishedAt || item.createdAt,
    tags: item.tags || [],
  });
});


// helper: convert admin form payload to model fields
const NewsUpsertSchema = z.object({
  title: z.string().min(2),
  slug: z.string().trim().min(2).optional(),
  blurb: z.string().max(300).optional().default(""),
  content: z.string().optional().default(""),
  coverUrl: z.string().optional().default(""),
  tags: z.array(z.string()).optional().default([]),
  // admin UI sends: date (YYYY-MM-DD) + published boolean
  date: z.string().optional(),            // e.g. "2025-10-23"
  published: z.boolean().optional().default(true),
});

// All /admin/news routes require admin+MFA
app.use("/admin/news", requireAdminAndMfa);

// LIST (admin)
app.get("/admin/news", async (req, res) => {
  const { page = "1", limit = "20", q } = req.query;
  const p = Math.max(parseInt(page), 1);
  const l = Math.max(parseInt(limit), 1);

  const where = { deletedAt: null };
  if (q) {
    where.$or = [
      { title: { $regex: q, $options: "i" } },
      { slug: { $regex: q, $options: "i" } },
      { blurb: { $regex: q, $options: "i" } },
    ];
  }

  const [items, total] = await Promise.all([
    News.find(where).sort({ createdAt: -1 }).skip((p - 1) * l).limit(l).lean(),
    News.countDocuments(where),
  ]);

  // shape it for your Admin.jsx (expects `date` + `published`)
  const out = items.map(n => ({
    _id: n._id,
    title: n.title,
    slug: n.slug,
    blurb: n.blurb,
    content: n.content,
    coverUrl: n.coverUrl,
    tags: n.tags || [],
    date: (n.publishedAt || n.createdAt),
    published: n.status === "published",
  }));

  res.json({ items: out, total });
});

// CREATE
app.post("/admin/news", requireCsrf, async (req, res) => {
  try {
    const body = NewsUpsertSchema.parse(req.body);
    const slug = (body.slug && body.slug.trim()) ||
      (await import("slugify")).default(body.title, { lower: true, strict: true });

    const publishedAt = body.published
      ? (body.date ? new Date(body.date) : new Date())
      : null;

    const doc = await News.create({
      title: body.title,
      slug,
      blurb: body.blurb,
      content: body.content,
      coverUrl: body.coverUrl,
      tags: body.tags,
      status: body.published ? "published" : "draft",
      publishedAt,
    });

    res.status(201).json({ ok: true, item: doc });
  } catch (e) {
    // duplicate slug -> 409
    if (e?.code === 11000 && e?.keyPattern?.slug) {
      return res.status(409).json({ ok: false, error: "Slug already exists" });
    }
    if (e?.issues) return res.status(400).json({ ok: false, error: "Validation failed", details: e.issues });
    console.error(e);
    res.status(500).json({ ok: false, error: "Server error" });
  }
});

// UPDATE
app.patch("/admin/news/:id", requireCsrf, async (req, res) => {
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) return res.status(400).json({ ok: false, error: "Bad id" });

  try {
    const body = NewsUpsertSchema.partial().parse(req.body);

    const update = {};
    if (body.title !== undefined) update.title = body.title;
    if (body.slug !== undefined) update.slug = body.slug.trim();
    if (body.blurb !== undefined) update.blurb = body.blurb;
    if (body.content !== undefined) update.content = body.content;
    if (body.coverUrl !== undefined) update.coverUrl = body.coverUrl;
    if (body.tags !== undefined) update.tags = body.tags;

    // handle published/status + date
    if (body.published !== undefined) {
      update.status = body.published ? "published" : "draft";
      if (body.published) {
        update.publishedAt = body.date ? new Date(body.date) : new Date();
      } else {
        update.publishedAt = null;
      }
    } else if (body.date !== undefined) {
      update.publishedAt = body.date ? new Date(body.date) : null;
    }

    const doc = await News.findByIdAndUpdate(id, { $set: update }, { new: true, runValidators: true });
    if (!doc) return res.status(404).json({ ok: false, error: "Not found" });

    res.json({ ok: true, item: doc });
  } catch (e) {
    if (e?.code === 11000 && e?.keyPattern?.slug) {
      return res.status(409).json({ ok: false, error: "Slug already exists" });
    }
    if (e?.issues) return res.status(400).json({ ok: false, error: "Validation failed", details: e.issues });
    console.error(e);
    res.status(500).json({ ok: false, error: "Server error" });
  }
});

// DELETE (soft delete)
app.delete("/admin/news/:id", requireCsrf, async (req, res) => {
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) return res.status(400).json({ ok: false, error: "Bad id" });

  const doc = await News.findByIdAndUpdate(id, { $set: { deletedAt: new Date() } }, { new: true });
  if (!doc) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true, item: doc });
});


app.post("/admin/news/:id/restore", requireCsrf, async (req, res) => {
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) return res.status(400).json({ ok: false, error: "Bad id" });
  const doc = await News.findByIdAndUpdate(id, { $set: { deletedAt: null } }, { new: true });
  if (!doc) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true, item: doc });
});


// app.post("/admin/login", requireCsrf, async (req, res) => {
//   const { email, password } = req.body || {};
//   if (!email || !password) {
//     return res.status(400).json({ ok: false, error: "Missing credentials" });
//   }

//   const user = await AdminUser.findOne({ email });
//   if (!user) {
//     return res.status(401).json({ ok: false, error: "Invalid credentials" });
//   }

//   const ok = await bcrypt.compare(password, user.passwordHash);
//   if (!ok) {
//     return res.status(401).json({ ok: false, error: "Invalid credentials" });
//   }

//   // baseline session
//   req.session.admin = true;
//   req.session.email = email;
//   req.session.mfaVerified = false;
//   user.lastLoginAt = new Date();
//   await user.save();

//   const enrolled = !!user.mfaSecret;
//   return res.json({ ok: true, mfaRequired: true, enrolled });
// });

app.post("/admin/login", requireCsrf, async (req, res) => {
  const { email, password } = req.body || {};
  const ip = getClientIp(req);
  const ua = req.headers["user-agent"] || "";

  // Basic validation
  if (!email || !password) {
    await AdminAuthLog.create({ email: email || "", ip, ua, success: false, reason: "missing_credentials" });
    return res.status(400).json({ ok: false, error: "Missing credentials" });
  }

  // Check lock status
  const now = new Date();
  let lock = await AdminAuthLock.findOne({ email });

  if (lock?.lockUntil && lock.lockUntil > now) {
    const remainingMs = lock.lockUntil - now;
    const mins = Math.ceil(remainingMs / 60000);
    await AdminAuthLog.create({ email, ip, ua, success: false, reason: "locked" });
    return res.status(423).json({
      ok: false,
      error: "Account locked due to repeated failed attempts",
      locked: true,
      minutesRemaining: mins,
      unlockAt: lock.lockUntil,
    });
  }

  // Find user
  const user = await AdminUser.findOne({ email });
  if (!user) {
    // increment failed count
    if (!lock) lock = await AdminAuthLock.create({ email, failedCount: 0 });
    lock.failedCount = (lock.failedCount || 0) + 1;
    lock.lastFailedAt = now;

    if (lock.failedCount >= AUTH_MAX_FAILED) {
      lock.lockUntil = new Date(now.getTime() + AUTH_LOCK_MINUTES * 60000);
    }
    await lock.save();

    await AdminAuthLog.create({ email, ip, ua, success: false, reason: "user_not_found" });
    return res.status(401).json({ ok: false, error: "Invalid credentials" });
  }

  // Compare password
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    if (!lock) lock = await AdminAuthLock.create({ email, failedCount: 0 });
    lock.failedCount = (lock.failedCount || 0) + 1;
    lock.lastFailedAt = now;

    if (lock.failedCount >= AUTH_MAX_FAILED) {
      lock.lockUntil = new Date(now.getTime() + AUTH_LOCK_MINUTES * 60000);
    }
    await lock.save();

    await AdminAuthLog.create({ email, ip, ua, success: false, reason: "invalid_password" });
    return res.status(401).json({ ok: false, error: "Invalid credentials" });
  }

  // Success → reset lock info
  if (lock) {
    lock.failedCount = 0;
    lock.lockUntil = null;
    await lock.save();
  }

  // baseline session
  req.session.admin = true;
  req.session.email = email;
  req.session.mfaVerified = false;

  user.lastLoginAt = new Date();
  await user.save();

  // Check for remembered device
  const rememberedMarker = req.body?.deviceMarker;
  if (rememberedMarker && (await isTrustedDevice(email, rememberedMarker))) {
    req.session.mfaVerified = true;
    await AdminAuthLog.create({ email, ip, ua, success: true, reason: "trusted_device" });
    return res.json({ ok: true, mfaRequired: false });
  }

  await AdminAuthLog.create({ email, ip, ua, success: true, reason: "" });

  const enrolled = !!user.mfaSecret;
  return res.json({ ok: true, mfaRequired: true, enrolled });
});



app.post("/admin/logout", requireAdmin, requireCsrf, (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

// protect your admin data routes with this middleware
app.use("/admin/messages", requireAdminAndMfa);
app.use("/admin/users", requireAdminAndMfa);


app.get("/admin/messages", requireAdmin, async (req, res) => {
  const { page = "1", limit = "20", read, q, includeDeleted = "false" } = req.query;
  const skip = (Math.max(parseInt(page), 1) - 1) * Math.max(parseInt(limit), 1);
  const where = {};
  if (read === "true") where.read = true;
  if (read === "false") where.read = false;
  if (includeDeleted !== "true") where.deletedAt = null;
  if (q) {
    where.$or = [
      { name: { $regex: q, $options: "i" } },
      { email: { $regex: q, $options: "i" } },
      { company: { $regex: q, $options: "i" } },
      { message: { $regex: q, $options: "i" } },
    ];
  }
  const [items, total] = await Promise.all([
    ContactMessage.find(where).sort({ createdAt: -1 }).skip(skip).limit(Math.max(parseInt(limit), 1)),
    ContactMessage.countDocuments(where),
  ]);
  res.json({ ok: true, items, total });
});

app.patch("/admin/messages/:id", requireCsrf, async (req, res) => {
  const { id } = req.params;
  const { read } = req.body || {};
  if (!mongoose.isValidObjectId(id)) return res.status(400).json({ ok: false, error: "Bad id" });
  const doc = await ContactMessage.findByIdAndUpdate(id, { $set: { read: !!read } }, { new: true });
  if (!doc) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true, item: doc });
});

app.delete("/admin/messages/:id", requireCsrf, async (req, res) => {
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) return res.status(400).json({ ok: false, error: "Bad id" });
  const doc = await ContactMessage.findByIdAndUpdate(id, { $set: { deletedAt: new Date() } }, { new: true });
  if (!doc) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true, item: doc });
});

// List (with simple search + pagination)
app.get("/admin/news", async (req, res) => {
  const { q = "", page = "1", limit = "20" } = req.query;
  const p = Math.max(parseInt(page), 1);
  const l = Math.max(parseInt(limit), 1);
  const where = q
    ? {
      $or: [{ title: { $regex: q, $options: "i" } },
      { blurb: { $regex: q, $options: "i" } },
      { slug: { $regex: q, $options: "i" } }]
    }
    : {};
  const [items, total] = await Promise.all([
    News.find(where).sort({ date: -1, createdAt: -1 }).skip((p - 1) * l).limit(l).lean(),
    News.countDocuments(where)
  ]);
  res.json({ ok: true, items, total });
});

// Create
app.post("/admin/news", requireCsrf, async (req, res) => {
  const data = NewsCreateSchema.parse(req.body);
  const exists = await News.findOne({ slug: data.slug });
  if (exists) return res.status(409).json({ ok: false, error: "Slug already exists" });
  const doc = await News.create({
    ...data,
    date: new Date(data.date),
  });
  res.status(201).json({ ok: true, item: doc });
});

// Update by id
app.patch("/admin/news/:id", requireCsrf, async (req, res) => {
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) return res.status(400).json({ ok: false, error: "Bad id" });
  const data = NewsUpdateSchema.parse(req.body);
  if (data.slug) {
    const dup = await News.findOne({ _id: { $ne: id }, slug: data.slug });
    if (dup) return res.status(409).json({ ok: false, error: "Slug already exists" });
  }
  if (data.date) data.date = new Date(data.date);
  const doc = await News.findByIdAndUpdate(id, { $set: data }, { new: true });
  if (!doc) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true, item: doc });
});

// Delete by id
app.delete("/admin/news/:id", requireCsrf, async (req, res) => {
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) return res.status(400).json({ ok: false, error: "Bad id" });
  const r = await News.deleteOne({ _id: id });
  if (!r.deletedCount) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true });
});


// ---------- Admin Users ----------
import mongoosePkg from "mongoose"; // if not already available as mongoose.*
const { isValidObjectId } = mongoosePkg || mongoose;

app.get("/admin/users", async (req, res) => {
  const users = await AdminUser.find({}, { // projection: only safe fields
    email: 1, name: 1, disabled: 1, lastLoginAt: 1, createdAt: 1,
  }).sort({ createdAt: -1 }).lean();
  res.json({ ok: true, items: users });
});

app.post("/admin/users", requireCsrf, async (req, res) => {
  const { email, name, password } = NewUserSchema.parse(req.body);
  const exists = await AdminUser.findOne({ email });
  if (exists) return res.status(409).json({ ok: false, error: "Email already exists" });
  const passwordHash = await bcrypt.hash(password, 12);
  const doc = await AdminUser.create({ email, name, passwordHash, disabled: false });
  res.status(201).json({ ok: true, id: doc._id });
});

app.patch("/admin/users/:id", requireCsrf, async (req, res) => {
  const { id } = req.params;
  if (!isValidObjectId(id)) return res.status(400).json({ ok: false, error: "Bad id" });

  const data = UpdateUserSchema.parse(req.body);
  const update = { ...("name" in data ? { name: data.name } : {}), ...("disabled" in data ? { disabled: data.disabled } : {}) };
  if (data.password) update.passwordHash = await bcrypt.hash(data.password, 12);

  const user = await AdminUser.findByIdAndUpdate(id, { $set: update }, { new: true });
  if (!user) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true, item: { _id: user._id, email: user.email, name: user.name, disabled: user.disabled } });
});

app.delete("/admin/users/:id", requireCsrf, async (req, res) => {
  const { id } = req.params;
  if (!isValidObjectId(id)) return res.status(400).json({ ok: false, error: "Bad id" });
  // Hard delete; switch to soft if you prefer
  const r = await AdminUser.deleteOne({ _id: id });
  if (!r.deletedCount) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true });
});

// Reset a user's MFA (forces re-enrol on next login)
app.post("/admin/users/:id/reset-mfa", requireCsrf, async (req, res) => {
  const { id } = req.params;
  if (!isValidObjectId(id)) return res.status(400).json({ ok: false, error: "Bad id" });
  const user = await AdminUser.findByIdAndUpdate(id, { $unset: { mfaSecret: 1 } }, { new: true });
  if (!user) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true });
});

app.get("/admin/me", requireAdmin, (req, res) => {
  res.json({ ok: true, email: req.session?.email || "admin" });
});

// GET /admin/auth-logs
app.get("/admin/auth-logs", requireAdmin, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || "1", 10));
    const limit = Math.max(1, Math.min(100, parseInt(req.query.limit || "50", 10)));
    const q = (req.query.q || "").trim();

    const filter = {};
    if (q) {
      filter.$or = [
        { email: new RegExp(q, "i") },
        { ip: new RegExp(q, "i") },
        { reason: new RegExp(q, "i") },
      ];
    }

    const total = await AdminAuthLog.countDocuments(filter);
    const items = await AdminAuthLog.find(filter)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    res.json({ ok: true, items, total });
  } catch (e) {
    console.error("AuthLog fetch failed", e);
    res.status(500).json({ error: "Failed to load auth logs" });
  }
});

// Optional: restore
app.post("/admin/messages/:id/restore", requireCsrf, async (req, res) => {
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) return res.status(400).json({ ok: false, error: "Bad id" });
  const doc = await ContactMessage.findByIdAndUpdate(id, { $set: { deletedAt: null } }, { new: true });
  if (!doc) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true, item: doc });
});

app.post("/admin/2fa/setup", requireCsrf, (req, res) => {
  if (!req.session?.admin) return res.status(401).json({ ok: false, error: "Unauthorized" });

  // If already enrolled, you can rotate by generating a new pending secret
  const secret = speakeasy.generateSecret({
    name: `CTRL Admin (api.ctrlcompliance.co.uk)`,
    length: 20,
  });

  req.session.mfaPendingSecret = secret.base32; // <— KEY NAME USED BY VERIFY

  QRCode.toDataURL(secret.otpauth_url, (err, dataUrl) => {
    if (err) return res.status(500).json({ ok: false, error: "QR error" });
    res.json({
      ok: true,
      secret: secret.base32,
      otpauth: secret.otpauth_url,
      qr: dataUrl,
    });
  });
});


app.post("/admin/2fa/verify", requireCsrf, async (req, res) => {
  if (!req.session?.admin) return res.status(401).json({ ok: false, error: "Unauthorized" });

  const { token } = req.body || {};
  if (!token) return res.status(400).json({ ok: false, error: "Missing token" });

  // Prefer pending secret (enrol flow); otherwise use saved secret (normal login)
  const pending = req.session.mfaPendingSecret;
  const saved = await getPersistedMfaSecret(req.session.email);
  const secret = pending || saved;

  if (!secret) {
    return res.status(400).json({ ok: false, error: "Not enrolled" });
  }

  const valid = speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token,
    window: 1, // tolerate ±30s drift

  });

  if (!valid) return res.status(401).json({ ok: false, error: "Invalid code" });

  // first-time enrol: persist secret and clear pending
  if (pending && !saved) {
    await setPersistedMfaSecret(req.session.email, pending);
    delete req.session.mfaPendingSecret;
  }

  // mark this session as MFA-verified
  req.session.mfaVerified = true;

  // Handle "remember this browser"
  const { remember } = req.body || {};
  if (remember) {
    const marker = crypto.randomBytes(24).toString("hex");
    await addTrustedDevice(req.session.email, marker);
    return res.json({ ok: true, deviceMarker: marker });
  }

  return res.json({ ok: true });

});



//Blog section
// ---------- ADMIN BLOGS ----------
app.get("/admin/blogs", requireAdmin, async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
  const q = (req.query.q || "").trim();

  const filter = { deletedAt: null };
  if (q) {
    const rx = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    Object.assign(filter, {
      $or: [
        { title: rx }, { slug: rx }, { blurb: rx }, { content: rx }, { tags: rx }, { author: rx },
      ],
    });
  }

  const [items, total] = await Promise.all([
    Blog.find(filter)
      .sort({ date: -1, _id: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
    Blog.countDocuments(filter),
  ]);

  res.json({ ok: true, items, total, page, limit });
});

app.post("/admin/blogs", requireAdmin, requireMfa, requireCsrf, async (req, res) => {
  const { title, slug, date, blurb, content, published, author, tags = [], heroUrl } = req.body || {};
  if (!title) return res.status(400).json({ ok: false, error: "Title is required" });
  const doc = await Blog.create({
    title,
    slug: slug || title.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-"),
    date: date ? new Date(date) : new Date(),
    blurb: blurb || "",
    content: content || "",
    published: !!published,
    author: author || "",
    tags: Array.isArray(tags) ? tags : [],
    heroUrl: heroUrl || "",
  });
  res.json({ ok: true, item: doc });
});

app.patch("/admin/blogs/:id", requireAdmin, requireMfa, requireCsrf, async (req, res) => {
  const { id } = req.params;
  const { title, slug, date, blurb, content, published, author, tags, heroUrl } = req.body || {};
  const update = {};
  if (title != null) update.title = title;
  if (slug != null) update.slug = slug;
  if (date != null) update.date = new Date(date);
  if (blurb != null) update.blurb = blurb;
  if (content != null) update.content = content;
  if (published != null) update.published = !!published;
  if (author != null) update.author = author;
  if (tags != null) update.tags = Array.isArray(tags) ? tags : [];
  if (heroUrl != null) update.heroUrl = heroUrl;
  update.updatedAt = new Date();

  const doc = await Blog.findByIdAndUpdate(id, update, { new: true });
  if (!doc) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true, item: doc });
});

app.delete("/admin/blogs/:id", requireAdmin, requireMfa, requireCsrf, async (req, res) => {
  const { id } = req.params;
  const doc = await Blog.findByIdAndUpdate(id, { deletedAt: new Date() }, { new: true });
  if (!doc) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true });
});

// ---------- PUBLIC BLOGS ----------
app.get("/blogs", async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 10));
  const q = (req.query.q || "").trim();
  const tag = (req.query.tag || "").trim();
  const includeUnpublished = req.query.includeUnpublished === "true"; // keep false in prod site

  const filter = { deletedAt: null };
  if (!includeUnpublished) filter.published = true;
  if (q) {
    const rx = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    Object.assign(filter, { $or: [{ title: rx }, { blurb: rx }, { content: rx }, { tags: rx }, { author: rx }] });
  }
  if (tag) filter.tags = tag;

  const [items, total] = await Promise.all([
    Blog.find(filter)
      .sort({ date: -1, _id: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .select("-content") // list view: omit heavy content
      .lean(),
    Blog.countDocuments(filter),
  ]);

  res.json({ ok: true, items, total, page, limit });
});

app.get("/blogs/:slug", async (req, res) => {
  const { slug } = req.params;
  const includeUnpublished = req.query.includeUnpublished === "true";
  const filter = { slug, deletedAt: null };
  if (!includeUnpublished) filter.published = true;

  const doc = await Blog.findOne(filter).lean();
  if (!doc) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true, item: doc });
});

// --- PUBLIC: List comments for a blog by slug (approved only) ---
app.get("/blogs/:slug/comments", async (req, res) => {
  const { slug } = req.params;
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));

  const blog = await Blog.findOne({ slug, deletedAt: null, published: true }).select("_id slug").lean();
  if (!blog) return res.status(404).json({ ok: false, error: "Blog not found" });

  const filter = { slug: blog.slug, blogId: blog._id, approved: true, deletedAt: null };
  const [items, total] = await Promise.all([
    BlogComment.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
    BlogComment.countDocuments(filter),
  ]);

  // only return public fields
  const publicItems = items.map(({ _id, name, body, createdAt }) => ({ _id, name, body, createdAt }));

  res.json({ ok: true, items: publicItems, total, page, limit });
});

// --- PUBLIC: Post a comment (awaiting approval) ---
app.post("/blogs/:slug/comments", express.json(), async (req, res) => {
  const { slug } = req.params;
  const { name, email, body, website } = req.body || {}; // website = honeypot

  // Honeypot (bots often fill this)
  if (website) return res.status(200).json({ ok: true }); // silently drop

  // Basic validation
  if (!name || !body || typeof name !== "string" || typeof body !== "string") {
    return res.status(400).json({ ok: false, error: "Name and comment are required" });
  }
  if (name.length > 80 || body.length > 4000) {
    return res.status(400).json({ ok: false, error: "Input too long" });
  }

  // Find blog
  const blog = await Blog.findOne({ slug, deletedAt: null, published: true }).select("_id slug").lean();
  if (!blog) return res.status(404).json({ ok: false, error: "Blog not found" });

  // Save (unapproved by default)
  const ip = (req.headers["x-forwarded-for"] || req.ip || "").toString().split(",")[0].trim();
  const ua = req.headers["user-agent"] || "";

  await BlogComment.create({
    blogId: blog._id,
    slug: blog.slug,
    name: name.trim(),
    email: (email || "").trim(),
    body: body.trim(),
    approved: false,
    ip, ua,
  });

  res.status(201).json({ ok: true, pending: true, message: "Thanks! Your comment is awaiting approval." });
});

// --- ADMIN: list comments (with filters) ---
app.get("/admin/blog-comments", requireAdmin, async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
  const approved = req.query.approved;
  const slug = (req.query.slug || "").trim();
  const q = (req.query.q || "").trim();

  const filter = { deletedAt: null };
  if (approved === "true") filter.approved = true;
  if (approved === "false") filter.approved = false;
  if (slug) filter.slug = slug;
  if (q) {
    const rx = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    Object.assign(filter, { $or: [{ name: rx }, { body: rx }, { email: rx }] });
  }

  const [items, total] = await Promise.all([
    BlogComment.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
    BlogComment.countDocuments(filter),
  ]);

  res.json({ ok: true, items, total, page, limit });
});

// --- ADMIN: approve / unapprove ---
app.patch("/admin/blog-comments/:id", requireAdmin, requireMfa, requireCsrf, async (req, res) => {
  const { id } = req.params;
  const { approved } = req.body || {};
  const doc = await BlogComment.findByIdAndUpdate(id, { approved: !!approved }, { new: true });
  if (!doc) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true, item: doc });
});

// --- ADMIN: delete (soft) ---
app.delete("/admin/blog-comments/:id", requireAdmin, requireMfa, requireCsrf, async (req, res) => {
  const { id } = req.params;
  const doc = await BlogComment.findByIdAndUpdate(id, { deletedAt: new Date() }, { new: true });
  if (!doc) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true });
});





const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`CTRL API listening on ${port}`));
