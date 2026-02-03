require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

// ===== Firebase Admin / Firestore =====
const admin = require("firebase-admin");

function getFirebaseConfig() {
  const raw = process.env.FIREBASE_CONFIG;
  if (!raw) {
    throw new Error("Missing FIREBASE_CONFIG in .env");
  }
  try {
    return JSON.parse(raw);
  } catch (e) {
    throw new Error("FIREBASE_CONFIG must be valid JSON (one line).");
  }
}

// يعتمد على Application Default Credentials (ADC)
// يعني لازم السيرفر يكون شغال في بيئة Google أو عنده ADC جاهزة.
// (مافيش Service Account هنا — بناءً على طلبك)
if (!admin.apps.length) {
  const firebaseConfig = getFirebaseConfig();
  admin.initializeApp(firebaseConfig);
}

const db = admin.firestore();

// ===== App =====
const app = express();
const PORT = process.env.PORT || 3000;

// ===== Middleware =====
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(
  cors({
    origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(",") : true,
    credentials: true,
  })
);

app.use(express.static(path.join(__dirname, "public")));

// ===== Helpers: JWT =====
function signAdminToken(payload) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error("JWT_SECRET is missing in .env");

  return jwt.sign(payload, secret, {
    expiresIn: process.env.JWT_EXPIRES_IN || "2h",
  });
}

function verifyToken(token) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error("JWT_SECRET is missing in .env");
  return jwt.verify(token, secret);
}

function checkJWT(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const bearerToken = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7)
      : null;
    const cookieToken = req.cookies?.admin_token;

    const token = bearerToken || cookieToken;
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== "admin") {
      return res.status(403).json({ error: "Forbidden" });
    }

    req.admin = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

function checkJWTForPage(req, res, next) {
  try {
    const token = req.cookies?.admin_token;
    if (!token) return res.redirect("/admin-login.html");

    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== "admin")
      return res.redirect("/admin-login.html");

    req.admin = decoded;
    next();
  } catch {
    return res.redirect("/admin-login.html");
  }
}

// ===== Nodemailer =====
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// ===== Utilities =====
function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

// ===== Routes عامة =====

// استقبال بيانات المستخدم من نموذج الموقع => Firestore
app.post("/api/submit", async (req, res) => {
  const { name, email, phone } = req.body;
  if (!name || !email || !phone) {
    return res.status(400).json({ error: "جميع الحقول مطلوبة" });
  }

  try {
    await db.collection("users").add({
      name: String(name),
      email: String(email),
      emailNorm: normalizeEmail(email),
      phone: String(phone),
      receivedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({ message: "تم استلام البيانات بنجاح" });
  } catch (e) {
    console.error("Firestore save user error:", e);
    res.status(500).json({ error: "فشل حفظ البيانات" });
  }
});

// ===== Admin Auth =====

app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;

  if (
    username === process.env.ADMIN_USERNAME &&
    password === process.env.ADMIN_PASSWORD
  ) {
    const token = signAdminToken({ username, role: "admin" });

    res.cookie("admin_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 2 * 60 * 60 * 1000,
    });

    return res.json({ message: "تم تسجيل الدخول بنجاح", token });
  }

  res.status(401).json({ error: "اسم المستخدم أو كلمة المرور غير صحيحة" });
});

app.post("/api/admin/logout", (req, res) => {
  res.clearCookie("admin_token");
  res.json({ message: "تم تسجيل الخروج بنجاح" });
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/admin-dashboard.html", checkJWTForPage, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin-dashboard.html"));
});

// ===== Admin APIs (محمي بـ JWT) =====

// جلب بيانات المستخدمين
app.get("/api/admin/users", checkJWT, async (req, res) => {
  try {
    const snap = await db.collection("users").orderBy("receivedAt", "desc").get();
    const users = snap.docs.map((d) => {
      const data = d.data() || {};
      return {
        id: d.id,
        name: data.name ?? "",
        email: data.email ?? "",
        phone: data.phone ?? "",
        receivedAt: data.receivedAt?.toDate ? data.receivedAt.toDate() : null,
      };
    });
    res.json(users);
  } catch (e) {
    console.error("Firestore get users error:", e);
    res.status(500).json({ error: "تعذر تحميل بيانات المستخدمين" });
  }
});

// حذف مستخدم بالبريد (متوافق مع فرونتك الحالي)
app.delete("/api/admin/user/:email", checkJWT, async (req, res) => {
  const email = decodeURIComponent(req.params.email || "");
  const emailNorm = normalizeEmail(email);
  if (!emailNorm) return res.status(400).json({ error: "بريد غير صالح" });

  try {
    const q = await db
      .collection("users")
      .where("emailNorm", "==", emailNorm)
      .limit(1)
      .get();

    if (q.empty) return res.status(404).json({ error: "المستخدم غير موجود" });

    await db.collection("users").doc(q.docs[0].id).delete();
    res.json({ message: `تم حذف المستخدم ${email} بنجاح` });
  } catch (e) {
    console.error("Firestore delete user error:", e);
    res.status(500).json({ error: "حدث خطأ أثناء الحذف" });
  }
});

// إرسال رسالة + حفظ في Firestore
app.post("/api/admin/message", checkJWT, async (req, res) => {
  const { email, message } = req.body;
  if (!email || !message) {
    return res.status(400).json({ error: "البريد الإلكتروني والرسالة مطلوبين" });
  }

  try {
    await transporter.sendMail({
      from: `"lab-results (معمل چون)" <${process.env.SMTP_USER}>`,
      to: String(email),
      subject: "lab-results (معمل چون)",
      text: String(message),
      html: `<p>${escapeHtml(message).replace(/\n/g, "<br/>")}</p>`,
    });

    const docRef = await db.collection("adminMessages").add({
      email: String(email),
      emailNorm: normalizeEmail(email),
      message: String(message),
      sentAt: admin.firestore.FieldValue.serverTimestamp(),
      by: req.admin?.username || "admin",
    });

    res.json({ message: "تم إرسال الرسالة بنجاح", id: docRef.id });
  } catch (err) {
    console.error("Email/Firestore error:", err);
    res.status(500).json({ error: "حدث خطأ أثناء إرسال الإيميل" });
  }
});

// جلب الرسائل
app.get("/api/admin/messages", checkJWT, async (req, res) => {
  try {
    const snap = await db
      .collection("adminMessages")
      .orderBy("sentAt", "desc")
      .get();

    const messages = snap.docs.map((d) => {
      const data = d.data() || {};
      return {
        id: d.id,
        email: data.email ?? "",
        message: data.message ?? "",
        sentAt: data.sentAt?.toDate ? data.sentAt.toDate() : null,
      };
    });

    res.json(messages);
  } catch (e) {
    console.error("Firestore get messages error:", e);
    res.status(500).json({ error: "تعذر تحميل الرسائل" });
  }
});

// حذف رسالة
app.delete("/api/admin/message", checkJWT, async (req, res) => {
  const { id, email } = req.body || {};

  try {
    if (id) {
      const ref = db.collection("adminMessages").doc(String(id));
      const doc = await ref.get();
      if (!doc.exists) return res.status(404).json({ error: "الرسالة غير موجودة" });
      await ref.delete();
      return res.json({ message: "تم حذف الرسالة بنجاح" });
    }

    if (!email) {
      return res.status(400).json({ error: "id أو البريد الإلكتروني مطلوب للحذف" });
    }

    const q = await db
      .collection("adminMessages")
      .where("emailNorm", "==", normalizeEmail(email))
      .orderBy("sentAt", "desc")
      .limit(1)
      .get();

    if (q.empty) return res.status(404).json({ error: "الرسالة غير موجودة" });

    await db.collection("adminMessages").doc(q.docs[0].id).delete();
    res.json({ message: "تم حذف الرسالة بنجاح" });
  } catch (e) {
    console.error("Firestore delete message error:", e);
    res.status(500).json({ error: "حدث خطأ أثناء الحذف" });
  }
});

// ===== Start =====
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
