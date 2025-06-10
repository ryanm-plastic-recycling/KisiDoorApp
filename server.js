// server.js
import ejs from "ejs";
import expressLayout from "express-ejs-layouts";
import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import Twilio from "twilio";

const app = express();
app.use(bodyParser.json({ verify: rawBodySaver }));
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(expressLayout);
// We need the raw body for HMAC. rawBodySaver attaches raw buffer to req.

const PORT = process.env.PORT || 3000;
const SIGNATURE_KEY = process.env.KISI_SIGNATURE_KEY || "";
const TWILIO_SID = process.env.TWILIO_ACCOUNT_SID || "";
const TWILIO_AUTH = process.env.TWILIO_AUTH_TOKEN || "";
const TWILIO_FROM = process.env.TWILIO_FROM_NUMBER || "";

// Initialize Twilio client
const twClient = Twilio(TWILIO_SID, TWILIO_AUTH);

// Path to our JSON config of recipients
const RECIPIENTS_FILE = path.join(__dirname, "config", "recipients.json");
const EVENTS_FILE = path.join(__dirname, "logs", "events.json");

function loadEvents() {
  try {
    const data = fs.readFileSync(EVENTS_FILE, "utf8");
    return JSON.parse(data);
  } catch {
    return [];
  }
}

function addEvent(entry) {
  const list = loadEvents();
  list.unshift({ timestamp: new Date().toISOString(), ...entry });
  fs.writeFileSync(EVENTS_FILE, JSON.stringify(list, null, 2));
}

// Track recent successful unlocks to detect door opens without a badge
const recentUnlocks = new Map();

// ── Helper to attach raw body ───────────────────────────────────────────────────
function rawBodySaver(req, res, buf, encoding) {
  if (buf && buf.length) {
    // Attach raw string for HMAC verification
    req.rawBody = buf.toString(encoding || "utf8");
  }
}

// ── Helper: Read All Recipients for Dashboard ─────────────────────────────────
function getAllRecipients() {
  try {
    const data = fs.readFileSync(RECIPIENTS_FILE, "utf8");
    return JSON.parse(data);
  } catch {
    return [];
  }
}

// ── Route: Dashboard ──────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  const recipients = getAllRecipients();
  res.render("dashboard", { recipients });
});

app.get("/events", (req, res) => {
  const q = (req.query.q || "").toLowerCase();
  let events = loadEvents();
  if (q) {
    events = events.filter((e) => JSON.stringify(e).toLowerCase().includes(q));
  }
  res.render("events", { events, query: req.query.q || "" });
});

// ── Route: Add Recipient ───────────────────────────────────────────────────────
app.post("/recipients/add", (req, res) => {
  const { name, phone } = req.body;
  if (!name || !phone) return res.redirect("/");

  const list = getAllRecipients();
  list.push({ name, phone });
  fs.writeFileSync(RECIPIENTS_FILE, JSON.stringify(list, null, 2));
  res.redirect("/");
});

// ── Route: Delete Recipient ───────────────────────────────────────────────────
app.post("/recipients/delete", (req, res) => {
  const { phone } = req.body;
  let list = getAllRecipients();
  list = list.filter((r) => r.phone !== phone);
  fs.writeFileSync(RECIPIENTS_FILE, JSON.stringify(list, null, 2));
  res.redirect("/");
});

// ── Route: Lockdown All Main Doors ────────────────────────────────────────────
const KISI_API_KEY = process.env.KISI_API_KEY || "";  
// You need an Admin API key that has rights to call Lockdown endpoints.

const MAIN_DOOR_IDS = [1234, 5678]; // ← Replace with your actual Lock IDs

app.post("/lockdown", async (req, res) => {
  if (!KISI_API_KEY) {
    console.error("No KISI_API_KEY set in environment.");
    return res.status(500).send("Server misconfiguration");
  }
  try {
    for (const lockId of MAIN_DOOR_IDS) {
      await TwilioFetch(`https://api.kisi.com/locks/${lockId}/lockdown`, "POST", {
        Authorization: `KISI-LOGIN ${KISI_API_KEY}`
      });
    }
    // After lockdown, notify via SMS
    const msg = `🔒 All main doors lockdown activated at ${new Date().toISOString()}.`;
    await broadcastSms(msg);
    addEvent({ kind: "action", action: "lockdown" });
    res.redirect("/");
  } catch (err) {
    console.error("Lockdown error:", err);
    res.status(500).send("Failed to lockdown");
  }
});

app.post("/locks/open", async (req, res) => {
  const { lockId } = req.body;
  if (!KISI_API_KEY || !lockId) return res.redirect("/");
  try {
    await TwilioFetch(`https://api.kisi.com/locks/${lockId}/unlock`, "POST", {
      Authorization: `KISI-LOGIN ${KISI_API_KEY}`
    });
    addEvent({ kind: "action", action: "open", lockId });
    res.redirect("/");
  } catch (err) {
    console.error("Open door error:", err);
    res.status(500).send("Failed to open door");
  }
});

app.post("/locks/unlock", async (req, res) => {
  const { lockId } = req.body;
  if (!KISI_API_KEY || !lockId) return res.redirect("/");
  try {
    await TwilioFetch(`https://api.kisi.com/locks/${lockId}/unlock`, "POST", {
      Authorization: `KISI-LOGIN ${KISI_API_KEY}`
    });
    addEvent({ kind: "action", action: "unlock", lockId });
    res.redirect("/");
  } catch (err) {
    console.error("Unlock door error:", err);
    res.status(500).send("Failed to unlock door");
  }
});

app.post("/locks/lock", async (req, res) => {
  const { lockId } = req.body;
  if (!KISI_API_KEY || !lockId) return res.redirect("/");
  try {
    await TwilioFetch(`https://api.kisi.com/locks/${lockId}/lock`, "POST", {
      Authorization: `KISI-LOGIN ${KISI_API_KEY}`
    });
    addEvent({ kind: "action", action: "lock", lockId });
    res.redirect("/");
  } catch (err) {
    console.error("Lock door error:", err);
    res.status(500).send("Failed to lock door");
  }
});

// ── Simple Fetch Wrapper using Twilio's node-fetch or built-in fetch ─────────
import fetch from "node-fetch";

async function TwilioFetch(url, method = "GET", headers = {}, body = {}) {
  return fetch(url, {
    method,
    headers: {
      "Accept": "application/json",
      "Content-Type": "application/json",
      ...headers
    },
    body: method === "GET" ? undefined : JSON.stringify(body)
  });
}

// ── Verify HMAC Signature ───────────────────────────────────────────────────────
function verifySignature(rawBody, signatureHeader) {
  if (!SIGNATURE_KEY) return true; // No signature configured → skip verification

  // Compute HMAC-SHA256
  const computed = crypto
    .createHmac("sha256", SIGNATURE_KEY)
    .update(rawBody)
    .digest("hex");

  return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(signatureHeader));
}

// ── Load Recipients from JSON ──────────────────────────────────────────────────
function loadRecipients() {
  try {
    const data = fs.readFileSync(RECIPIENTS_FILE, "utf8");
    return JSON.parse(data);
  } catch (err) {
    console.error("Failed to read recipients.json:", err);
    return [];
  }
}

// ── Send SMS to All Recipients ──────────────────────────────────────────────────
async function broadcastSms(message) {
  const recipients = loadRecipients();
  for (const entry of recipients) {
    const to = entry.phone;
    const name = entry.name;
    const personalized = `Hi ${name},\n${message}`;

    try {
      await twClient.messages.create({
        from: TWILIO_FROM,
        to,
        body: personalized
      });
      console.log(`SMS sent to ${to}`);
      addEvent({ kind: "sms", to, body: personalized });
    } catch (err) {
      console.error(`Failed to send SMS to ${to}:`, err);
    }
  }
}

// ── Webhook Endpoint ───────────────────────────────────────────────────────────
app.post("/api/kisi/webhook", (req, res) => {
  const signature = req.headers["x-signature"] || "";
  const rawBody = req.rawBody || "";

  // 1) Verify signature (if configured)
  if (SIGNATURE_KEY && !verifySignature(rawBody, signature)) {
    console.warn("❌ Invalid HMAC signature; ignoring payload.");
    return res.status(401).send("Invalid signature");
  }

  // 2) Parse event
  const event = req.body;
  if (!event || !event.type) {
    return res.status(400).send("Invalid payload");
  }

  addEvent({ kind: "kisi", event });

  // Record successful unlocks
  if (event.type === "lock.unlock" && event.success) {
    recentUnlocks.set(event.object_id, Date.now());
  }

  // Access denied alert
  if (event.type === "lock.unlock_failed") {
    const who = event.actor_name || `ID ${event.actor_id}`;
    const door = event.object_name || `Lock ${event.object_id}`;
    const ts = event.created_at;
    const msg = `🚨 Access Denied: ${who} attempted to open "${door}" at ${ts}.`;
    console.log(msg);
    broadcastSms(msg).catch((err) => console.error("SMS broadcast error:", err));
  }

  // Forced open or tampered reader
  if (event.type === "lock.force_open") {
    const door = event.object_name || `Lock ${event.object_id}`;
    const msg = `🚨 Forced Open detected on "${door}" at ${event.created_at}.`;
    console.log(msg);
    broadcastSms(msg);
  }

  if (event.type === "reader.tampered") {
    const device = event.object_name || `Reader ${event.object_id}`;
    const msg = `🚨 Tamper Alert: ${device} at ${event.created_at}.`;
    console.log(msg);
    broadcastSms(msg);
  }

  // Door opened event without prior unlock
  if (event.type === "lock.open") {
    const last = recentUnlocks.get(event.object_id) || 0;
    if (Date.now() - last > 5000) {
      const door = event.object_name || `Lock ${event.object_id}`;
      const msg = `‼️ Door "${door}" opened without badge at ${event.created_at}.`;
      console.log(msg);
      broadcastSms(msg);
    } else {
      recentUnlocks.delete(event.object_id);
    }
  }

  // Always 200 OK so Kisi does not retry indefinitely
  res.status(200).send("OK");
});

// ── Start Server ───────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ Kisi Notifier running on port ${PORT}`);
});
