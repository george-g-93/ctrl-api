import express from "express";
import cors from "cors";

const app = express();
// CORS – allow your web origin
app.use(cors({
  origin: ["https://ctrlcompliance.co.uk", "https://www.ctrlcompliance.co.uk"],
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json());

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

// // --- CONTACT ROUTE ---
// app.post("/contact", contactLimiter, async (req, res) => {
//   try {
//     // simple bot trap: reject if honeypot field filled
//     if (typeof req.body.website === "string" && req.body.website.trim() !== "") {
//       return res.status(204).end(); // quietly ignore spam
//     }

//     const data = ContactSchema.parse(req.body);

//     const doc = await ContactMessage.create({
//       ...data,
//       ip: req.headers["x-forwarded-for"]?.toString().split(",")[0] ?? req.ip,
//       ua: req.headers["user-agent"] ?? "",
//     });

//     return res.status(201).json({ ok: true, id: doc._id });
//   } catch (err) {
//     if (err?.issues) {
//       return res.status(400).json({ ok: false, error: "Validation failed", details: err.issues });
//     }
//     console.error(err);
//     return res.status(500).json({ ok: false, error: "Server error" });
//   }
// });

app.post("/contact", (req, res) => {
  res.status(201).json({ ok: true, echo: req.body ?? null });
});

app.get("/news", (_req, res) => {
  const sorted = [...news].sort((a,b) => new Date(b.date) - new Date(a.date));
  res.json(sorted);
});
app.get("/news/:id", (req, res) => {
  const item = news.find(n => n.id === req.params.id);
  if (!item) return res.status(404).json({ error: "Not found" });
  res.json(item);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`CTRL API listening on ${port}`));
