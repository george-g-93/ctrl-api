import express from "express";
import cors from "cors";

const app = express();
app.use(cors());
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
