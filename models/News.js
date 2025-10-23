// FILE: src/pages/News.jsx
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Link } from "react-router-dom";

const API = import.meta.env.VITE_API_BASE?.replace(/\/+$/, "") || "";

export default function News() {
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const r = await fetch(`${API}/news`, { cache: "no-store" });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();
        // Expecting [{ slug, title, blurb, date }]
        if (alive) setPosts(Array.isArray(data) ? data : []);
      } catch (e) {
        if (alive) setErr("Couldn't load news right now.");
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => { alive = false; };
  }, []);

  return (
    <section className="mx-auto max-w-6xl px-6 py-16">
      <h1 className="text-4xl font-semibold tracking-tight">News</h1>
      <p className="mt-2 text-slate-600 dark:text-slate-400">
        Updates from CTRL—guides, releases, and events.
      </p>

      {loading && <p className="mt-8 text-slate-500 dark:text-slate-400">Loading…</p>}
      {err && !loading && <p className="mt-8 text-rose-500 dark:text-rose-300">{err}</p>}

      {!loading && !err && (
        <div className="mt-8 grid gap-6 sm:grid-cols-2">
          {posts.map((p, i) => (
            <motion.article
              key={p.slug}
              initial={{ opacity: 0, y: 8 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.3 }}
              transition={{ delay: i * 0.05 }}
              className="rounded-2xl border p-6 border-slate-200 bg-white shadow-sm dark:border-white/10 dark:bg-white/5"
            >
              <div className="text-xs text-slate-500 dark:text-slate-400">
                {p.date ? new Date(p.date).toLocaleDateString() : ""}
              </div>

              <h2 className="mt-1 text-xl font-semibold">
                <Link
                  to={`/news/${p.slug}`}
                  className="text-slate-900 hover:text-emerald-700 dark:text-slate-100 dark:hover:text-emerald-300"
                >
                  {p.title}
                </Link>
              </h2>

              <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                {p.blurb}
              </p>

              <Link to={`/news/${p.slug}`} className="mt-4 inline-block text-xs border border-slate-300 rounded-xl px-3 py-1.5 hover:bg-slate-50 dark:border-white/15 dark:hover:bg-white/10">
                Read more
              </Link>
            </motion.article>
          ))}
          {posts.length === 0 && (
            <div className="text-sm text-slate-500">No posts yet.</div>
          )}
        </div>
      )}
    </section>
  );
}
