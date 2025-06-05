// server.js
import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import Twilio from "twilio";

const app = express();
app.use(bodyParser.json({ verify: rawBodySaver }));  
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

// ── Helper to attach raw body ───────────────────────────────────────────────────
function rawBodySaver(req, res, buf, encoding) {
  if (buf && buf.length) {
    // Attach raw string for HMAC verification
    req.rawBody = buf.toString(encoding || "utf8");
  }
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

  // 3) If it’s an "unlock_failed" event → compose SMS
  if (event.type === "lock.unlock_failed") {
    const who = event.actor_name || `ID ${event.actor_id}`;
    const door = event.object_name || `Lock ${event.object_id}`;
    const ts = event.created_at;
    const msg = `🚨 Access Denied: ${who} attempted to open "${door}" at ${ts}.`;

    console.log(msg);
    broadcastSms(msg).catch((err) => console.error("SMS broadcast error:", err));
  }
  // 4) (Optional) Handle forced open / tamper here, see Section 3

  // Always 200 OK so Kisi does not retry indefinitely
  res.status(200).send("OK");
});

// ── Start Server ───────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ Kisi Notifier running on port ${PORT}`);
});
