// תזכורת "בעוד שעה משחק" – Netlify מריץ את זה לבד כל רבע שעה (לא צריך להגדיר כלום)
import { getStore } from "@netlify/blobs";
import { runReminders } from "./api.mjs";

export default async () => {
  const origin = process.env.URL || "https://example.netlify.app";
  try {
    const r = await runReminders(getStore({ name: "league-data", consistency: "strong" }), getStore({ name: "league-push", consistency: "strong" }), origin);
    console.log("reminders", JSON.stringify(r));
  } catch (e) { console.error("reminders failed", e); }
};

export const config = { schedule: "*/15 * * * *" };
