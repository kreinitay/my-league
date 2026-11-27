// תזכורת "בעוד שעה משחק" – Netlify מריץ את זה לבד כל רבע שעה (לא צריך להגדיר כלום)
import { getStore } from "@netlify/blobs";
import { runReminders, ibbaSync } from "./api.mjs";

export default async () => {
  const origin = process.env.URL || "https://example.netlify.app";
  try {
    const r = await runReminders(getStore({ name: "league-data", consistency: "strong" }), getStore({ name: "league-push", consistency: "strong" }), origin);
    console.log("reminders", JSON.stringify(r));
  } catch (e) { console.error("reminders failed", e); }
  // תוצאות מאתר האיגוד: גם אם אף אחד לא פתח את האתר, תוצאה סופית נכנסת לבד
  try { const r = await ibbaSync(getStore({ name: "league-data", consistency: "strong" })); console.log("ibba", JSON.stringify({ ok: r.ok, changed: r.changed?.length || 0, error: r.error })); }
  catch (e) { console.error("ibba failed", e); }
};

export const config = { schedule: "*/15 * * * *" };
