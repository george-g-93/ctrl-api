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


const app = express();

app.set("trust proxy", 1); // behind Nginx
// CORS – allow your web origin
app.use(cors({
  origin: ["https://ctrlcompliance.co.uk", "https://www.ctrlcompliance.co.uk"],
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"],
  credentials: true,
}));
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
  secure: true, // requires HTTPS; you have it
  sameSite: "none", // allow cross-site from ctrlcompliance.co.uk to api.ctrl...
  domain: ".ctrlcompliance.co.uk", // cookie valid on both site + api subdomain
  maxAge: 1000 * 60 * 60 * 8, // 8 hours
}));

// in-memory demo data; swap to DynamoDB later
const news = [
  {
    id: "earned-recognition-pack",
    date: "2025-10-10",
    title: "CTRL launches Earned Recognition prep pack!",
    blurb: "A practical set of templates and checks aligned to DVSA ER KPIs.",
    content: "<p>We’ve released a practical pack…</p>"
  },
  {
    id: "drivers-hours-pitfalls",
    date: "2025-09-22",
    title: "Webinar recap: Drivers’ hours pitfalls",
    blurb: "Top 7 infringement patterns we keep seeing—and how to stop them."
  }
];

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

// --- Validation schema ---
const ContactSchema = z.object({
  name: z.string().min(2),
  company: z.string().optional().default(""),
  email: z.string().email(),
  fleetSize: z.string().optional().default(""),
  message: z.string().min(5),
  website: z.string().optional().default(""), // honeypot
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

app.get("/news", (_req, res) => {
  const sorted = [...news].sort((a, b) => new Date(b.date) - new Date(a.date));
  res.json(sorted);
});
app.get("/news/:id", (req, res) => {
  const item = news.find(n => n.id === req.params.id);
  if (!item) return res.status(404).json({ error: "Not found" });
  res.json(item);
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
  if (req.method === "GET") return next();
  if (req.session?.csrf && req.get("X-CSRF-Token") === req.session.csrf) return next();
  return res.status(403).json({ ok: false, error: "CSRF" });
};
const requireAdmin = (req, res, next) => {
  if (req.session?.admin === true) return next();
  return res.status(401).json({ ok: false, error: "Unauthorized" });
};

const requireMfa = (req, res, next) => {
  if (req.session?.mfa === true) return next();
  return res.status(401).json({ ok: false, error: "MFA required" });
};



app.post("/admin/login", requireCsrf, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ ok:false, error:"Missing credentials" });

  const ok = email === process.env.ADMIN_EMAIL &&
             await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH || "");
  if (!ok) return res.status(401).json({ ok:false, error:"Invalid credentials" });

  req.session.admin = true;
  req.session.email = email;
  req.session.mfa = false; // must prove 2nd factor next

  const hasSecret = !!process.env.ADMIN_TOTP_SECRET;
  return res.json({ ok:true, mfaRequired: true, enrolled: hasSecret });
});

app.post("/admin/logout", requireAdmin, requireCsrf, (req, res) => {
  req.session = null;
  res.json({ ok:true });
});

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

app.patch("/admin/messages/:id", requireAdmin, requireMfa, requireCsrf, async (req, res) => {
  const { id } = req.params;
  const { read } = req.body || {};
  if (!mongoose.isValidObjectId(id)) return res.status(400).json({ ok: false, error: "Bad id" });
  const doc = await ContactMessage.findByIdAndUpdate(id, { $set: { read: !!read } }, { new: true });
  if (!doc) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true, item: doc });
});

app.delete("/admin/messages/:id", requireAdmin, requireCsrf, async (req, res) => {
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) return res.status(400).json({ ok: false, error: "Bad id" });
  const doc = await ContactMessage.findByIdAndUpdate(id, { $set: { deletedAt: new Date() } }, { new: true });
  if (!doc) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true, item: doc });
});

// Optional: restore
app.post("/admin/messages/:id/restore", requireAdmin, requireCsrf, async (req, res) => {
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) return res.status(400).json({ ok: false, error: "Bad id" });
  const doc = await ContactMessage.findByIdAndUpdate(id, { $set: { deletedAt: null } }, { new: true });
  if (!doc) return res.status(404).json({ ok: false, error: "Not found" });
  res.json({ ok: true, item: doc });
});

app.post("/admin/2fa/setup", requireAdmin, requireCsrf, async (req, res) => {
  if (process.env.ADMIN_TOTP_SECRET) {
    return res.status(400).json({ ok:false, error:"Already enrolled" });
  }
  const secret = speakeasy.generateSecret({
    name: "CTRL Admin (api.ctrlcompliance.co.uk)",
    length: 20, // base32 will be ~32 chars
  });

  // persist secret (env for now). In production, store in DB or a secrets manager.
  console.warn("SAVE THIS TOTP SECRET (base32) IN ADMIN_TOTP_SECRET:", secret.base32);

  const otpauth = secret.otpauth_url;
  const qrDataUrl = await QRCode.toDataURL(otpauth);

  return res.json({ ok:true, secret: secret.base32, otpauth, qr: qrDataUrl });
});

app.post("/admin/2fa/verify", requireAdmin, requireCsrf, (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ ok:false, error:"Missing token" });
  const secret = process.env.ADMIN_TOTP_SECRET;
  if (!secret) return res.status(400).json({ ok:false, error:"Not enrolled" });

  const verified = speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token,
    window: 1, // allow small clock drift (+/- 30s)
    step: 30,
    digits: 6,
  });

  if (!verified) return res.status(401).json({ ok:false, error:"Invalid token" });
  req.session.mfa = true;
  return res.json({ ok:true });
});


const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`CTRL API listening on ${port}`));
