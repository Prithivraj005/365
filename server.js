// server.js - updated backend for 365 app (per-user, per-day media upload handling)
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const stream = require("stream");
const cloudinary = require("cloudinary").v2;
const morgan = require("morgan");

const app = express();
app.use(cors());
app.use(express.json());
app.use(morgan("dev")); // request logging

// ---------- ENV check ----------
const REQUIRED = ["MONGO_URI", "JWT_SECRET", "CLOUDINARY_CLOUD_NAME", "CLOUDINARY_API_KEY", "CLOUDINARY_API_SECRET"];
REQUIRED.forEach(k => {
  if (!process.env[k]) console.warn(`⚠️  Env var ${k} is not set`);
});

// ---------- MongoDB ----------
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => {
    console.error("Mongo connection failed:", err);
    process.exit(1);
  });

// ---------- Cloudinary ----------
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ---------- Multer ----------
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 300 * 1024 * 1024 } });

// ---------- Schemas & Models ----------
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
}, { timestamps: true });
const User = mongoose.models.User || mongoose.model("User", userSchema);

const mediaSubSchema = new mongoose.Schema({
  url: String,
  public_id: String,
  type: String,
  uploadedAt: { type: Date, default: Date.now }
}, { _id: false });

const dayEntrySchema = new mongoose.Schema({
  userId: { type: String, required: true }, // string to match frontend
  month: { type: Number, required: true }, // 0-11
  dayNumber: { type: Number, required: true }, // 1-31
  text: { type: String, default: "" },
  mood: { type: String, default: "" },
  media: [mediaSubSchema],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
// ensure one entry per user/day/month
dayEntrySchema.index({ userId: 1, month: 1, dayNumber: 1 }, { unique: true });
const DayEntry = mongoose.models.DayEntry || mongoose.model("DayEntry", dayEntrySchema);

// ---------- Helpers ----------
function makeToken(user) {
  return jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "30d" });
}

function authMiddleware(req, res, next) {
  try {
    const hdr = req.headers.authorization;
    if (!hdr) return res.status(401).json({ error: "No authorization header" });
    const token = hdr.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Malformed authorization header" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Unauthorized", details: err.message });
  }
}

function uploadToCloudinary(buffer, mimetype, filename = "file") {
  return new Promise((resolve, reject) => {
    let resource_type = "auto";
    if (mimetype && mimetype.startsWith("image")) resource_type = "image";
    else if (mimetype && mimetype.startsWith("video")) resource_type = "video";
    else if (mimetype && mimetype.startsWith("audio")) resource_type = "raw";

    const uploadStream = cloudinary.uploader.upload_stream(
      { resource_type, folder: "365_App", use_filename: true, unique_filename: false },
      (err, result) => {
        if (err) return reject(err);
        resolve(result);
      }
    );

    const pass = new stream.PassThrough();
    pass.end(buffer);
    pass.pipe(uploadStream);
  });
}

// ---------- Routes ----------

// Health check
app.get("/", (req, res) => res.send("✅ 365 backend running"));

// Signup
app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Missing username or password" });
    const exists = await User.findOne({ username });
    if (exists) return res.status(409).json({ error: "Username already taken" });
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password: hash });
    const token = makeToken(user);
    return res.json({ user: { username: user.username }, token });
  } catch (err) {
    console.error("Signup error:", err);
    return res.status(500).json({ error: "Signup failed", details: err.message });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Missing username or password" });
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: "User not found" });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });
    const token = makeToken(user);
    return res.json({ user: { username: user.username }, token });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Login failed", details: err.message });
  }
});

// POST /upload/:day - create or update per-user per-day entry
app.post("/upload/:day", authMiddleware, upload.array("files"), async (req, res) => {
  try {
    const dayParam = parseInt(req.params.day, 10);
    if (isNaN(dayParam) || dayParam < 1) return res.status(400).json({ error: "Invalid day param" });

    const monthClient = req.body?.month !== undefined && req.body.month !== "" ? parseInt(req.body.month, 10) : null;
    const month = typeof monthClient === "number" && !isNaN(monthClient) ? monthClient : (new Date()).getMonth();

    const text = typeof req.body.text === "string" ? req.body.text : undefined;
    const mood = typeof req.body.mood === "string" ? req.body.mood : undefined;

    const userId = req.userId;
    let entry = await DayEntry.findOne({ userId, month, dayNumber: dayParam });

    const uploadedMedia = [];
    if (req.files && req.files.length) {
      for (const f of req.files) {
        try {
          const r = await uploadToCloudinary(f.buffer, f.mimetype, f.originalname);
          uploadedMedia.push({
            url: r.secure_url || r.url || "",
            public_id: r.public_id || "",
            type: r.resource_type || (f.mimetype || "").split("/")[0] || "raw"
          });
        } catch (err) {
          console.error("Cloudinary upload failed for file", f.originalname, err);
        }
      }
    }

    if (!entry) {
      // create new day entry
      entry = new DayEntry({
        userId,
        month,
        dayNumber: dayParam,
        text: text ?? "",
        mood: mood ?? "",
        media: uploadedMedia
      });
    } else {
      // update text/mood if provided
      if (text !== undefined) entry.text = text;
      if (mood !== undefined) entry.mood = mood;

      // replace existing media of same type
      if (uploadedMedia.length) {
        for (const nm of uploadedMedia) {
          const sameType = entry.media.filter(m => m.type === nm.type);
          for (const old of sameType) {
            if (old.public_id) {
              try {
                await cloudinary.uploader.destroy(old.public_id, { resource_type: old.type || "auto", invalidate: true });
              } catch (err) {
                console.warn("Failed to destroy old media", old.public_id, err);
              }
            }
          }
          entry.media = entry.media.filter(m => m.type !== nm.type);
          entry.media.push(nm);
        }
      }
    }

    entry.updatedAt = new Date();
    await entry.save();

    const fresh = await DayEntry.findById(entry._id).lean();
    return res.json({ message: "Saved", dayEntry: fresh });
  } catch (err) {
    console.error("POST /upload/:day error:", err);
    return res.status(500).json({ error: "Upload failed", details: err.message });
  }
});

// PATCH /upload/:day - update text/mood or remove media
app.patch("/upload/:day", authMiddleware, async (req, res) => {
  try {
    const dayParam = parseInt(req.params.day, 10);
    if (isNaN(dayParam) || dayParam < 1) return res.status(400).json({ error: "Invalid day param" });

    const { month, text, mood, removePublicIds, removeUrls } = req.body || {};
    const m = typeof month === "number" && !isNaN(month) ? month : (new Date()).getMonth();
    const userId = req.userId;

    const query = { userId, month: m, dayNumber: dayParam };

    const setOps = {};
    if (typeof text === "string") setOps.text = text;
    if (typeof mood === "string") setOps.mood = mood;
    if (Object.keys(setOps).length) {
      setOps.updatedAt = new Date();
      await DayEntry.findOneAndUpdate(query, { $set: setOps }, { new: true, upsert: true, setDefaultsOnInsert: true });
    }

    if (Array.isArray(removePublicIds) && removePublicIds.length) {
      for (const pid of removePublicIds) {
        try {
          await cloudinary.uploader.destroy(pid, { resource_type: "auto", invalidate: true });
        } catch (err) {
          console.warn("Cloud destroy failed for", pid, err);
        }
      }
      await DayEntry.updateOne(query, { $pull: { media: { public_id: { $in: removePublicIds } } } });
    }

    if (Array.isArray(removeUrls) && removeUrls.length) {
      await DayEntry.updateOne(query, { $pull: { media: { url: { $in: removeUrls } } } });
    }

    const updated = await DayEntry.findOne(query).lean();
    return res.json({ message: "Patched", dayEntry: updated });
  } catch (err) {
    console.error("PATCH /upload/:day error:", err);
    return res.status(500).json({ error: "Patch failed", details: err.message });
  }
});

// GET all days for user
app.get("/days", authMiddleware, async (req, res) => {
  try {
    const list = await DayEntry.find({ userId: req.userId }).sort({ month: 1, dayNumber: 1 }).lean();
    const normalized = list.map(doc => {
      const media = (doc.media || []).map(m => ({
        url: m.url || "",
        type: m.type || "",
        public_id: m.public_id || ""
      }));
      return { ...doc, media };
    });
    return res.json({ list: normalized });
  } catch (err) {
    console.error("GET /days error:", err);
    return res.status(500).json({ error: "Failed to fetch days", details: err.message });
  }
});

// GET single day by month/day
app.get("/day/:month/:day", authMiddleware, async (req, res) => {
  try {
    const month = parseInt(req.params.month, 10);
    const day = parseInt(req.params.day, 10);
    if (isNaN(month) || isNaN(day)) return res.status(400).json({ error: "Invalid month/day" });
    const doc = await DayEntry.findOne({ userId: req.userId, month, dayNumber: day }).lean();
    return res.json({ dayEntry: doc || null });
  } catch (err) {
    console.error("GET /day error:", err);
    return res.status(500).json({ error: "Failed", details: err.message });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Backend listening on ${PORT}`));
