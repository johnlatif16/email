require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;

/**
 * ⚠️ تخزين مؤقت في الذاكرة (زي كودك الأصلي)
 * في Vercel/Serverless البيانات ممكن تروح مع إعادة تشغيل الـ instance
 */
const usersData = [];
const adminMessages = [];

// ===== Middleware الأساسي =====
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

/**
 * ✅ CORS
 * لو الفرونت على دومين مختلف، لازم تحدد origin + credentials
 * لو نفس الدومين، ممكن تبسطها.
 */
app.use(
  cors({
    origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : true,
    credentials: true
  })
);

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// ===== Helpers: JWT =====
function signAdminToken(payload) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET is missing in .env');

  return jwt.sign(payload, secret, {
    expiresIn: process.env.JWT_EXPIRES_IN || '2h'
  });
}

function verifyToken(token) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET is missing in .env');
  return jwt.verify(token, secret);
}

/**
 * Middleware للتحقق:
 * - Authorization: Bearer <token>
 * - أو Cookie: admin_token
 */
function checkJWT(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    const cookieToken = req.cookies?.admin_token;

    const token = bearerToken || cookieToken;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }

    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

/**
 * Middleware خاص بالصفحات (Redirect بدل JSON)
 * مهم عشان /admin-dashboard.html يفضل يحول للوجين لو مفيش توكن
 */
function checkJWTForPage(req, res, next) {
  try {
    const token = req.cookies?.admin_token;
    if (!token) return res.redirect('/admin-login.html');

    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'admin') return res.redirect('/admin-login.html');

    req.admin = decoded;
    next();
  } catch {
    return res.redirect('/admin-login.html');
  }
}

// ===== Nodemailer =====
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST, // smtp.gmail.com مثلاً
  port: Number(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// ===== Routes عامة =====

// استقبال بيانات المستخدم من نموذج الموقع
app.post('/api/submit', (req, res) => {
  const { name, email, phone } = req.body;
  if (!name || !email || !phone) {
    return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
  }

  usersData.push({ name, email, phone, receivedAt: new Date() });
  res.json({ message: 'تم استلام البيانات بنجاح' });
});

// ===== Admin Auth =====

// تسجيل دخول الادمن: يصدر JWT ويحطه في Cookie HttpOnly
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;

  if (
    username === process.env.ADMIN_USERNAME &&
    password === process.env.ADMIN_PASSWORD
  ) {
    const token = signAdminToken({ username, role: 'admin' });

    // Cookie HttpOnly
    res.cookie('admin_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // على https
      sameSite: 'lax',
      maxAge: 2 * 60 * 60 * 1000 // 2h
    });

    return res.json({ message: 'تم تسجيل الدخول بنجاح', token });
  }

  res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
});

// تسجيل خروج: نمسح الكوكي
app.post('/api/admin/logout', (req, res) => {
  res.clearCookie('admin_token');
  res.json({ message: 'تم تسجيل الخروج بنجاح' });
});

// صفحة الادمن (اختياري)
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// حماية الوصول لصفحة الداشبورد (Redirect للوجين لو مفيش توكن)
app.get('/admin-dashboard.html', checkJWTForPage, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

// ===== Admin APIs (محمي بـ JWT) =====

// جلب بيانات المستخدمين (محمي)
app.get('/api/admin/users', checkJWT, (req, res) => {
  res.json(usersData);
});

// حذف مستخدم معين بناءً على البريد (محمي)
app.delete('/api/admin/user/:email', checkJWT, (req, res) => {
  const email = decodeURIComponent(req.params.email);
  const index = usersData.findIndex((user) => user.email === email);

  if (index === -1) {
    return res.status(404).json({ error: 'المستخدم غير موجود' });
  }

  usersData.splice(index, 1);
  res.json({ message: `تم حذف المستخدم ${email} بنجاح` });
});

// إرسال رسالة (محمي) + إرسال إيميل فعلي
app.post('/api/admin/message', checkJWT, async (req, res) => {
  const { email, message } = req.body;

  if (!email || !message) {
    return res.status(400).json({ error: 'البريد الإلكتروني والرسالة مطلوبين' });
  }

  try {
    await transporter.sendMail({
      from: `"lab-results (معمل چون)" <${process.env.SMTP_USER}>`,
      to: email,
      subject: 'lab-results (معمل چون)',
      text: message,
      html: `<p>${escapeHtml(message).replace(/\n/g, '<br/>')}</p>`
    });

    // إضافة id بسيط (عشان الحذف يكون أدق لو حبيت)
    const id = `${Date.now()}_${Math.random().toString(16).slice(2)}`;
    adminMessages.push({ id, email, message, sentAt: new Date() });

    res.json({ message: 'تم إرسال الرسالة بنجاح' });
  } catch (err) {
    console.error('خطأ في إرسال الإيميل:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء إرسال الإيميل' });
  }
});

// جلب كل الرسائل (محمي) ✅ دلوقتي اتقفل
app.get('/api/admin/messages', checkJWT, (req, res) => {
  res.json(adminMessages);
});

// حذف رسالة (محمي)
// الأفضل: حذف بالـ id، ولو مش موجود يرجع لحذف أول رسالة لنفس email (للتوافق)
app.delete('/api/admin/message', checkJWT, (req, res) => {
  const { id, email } = req.body;

  if (id) {
    const index = adminMessages.findIndex((msg) => msg.id === id);
    if (index === -1) return res.status(404).json({ error: 'الرسالة غير موجودة' });
    adminMessages.splice(index, 1);
    return res.json({ message: 'تم حذف الرسالة بنجاح' });
  }

  if (!email) {
    return res.status(400).json({ error: 'id أو البريد الإلكتروني مطلوب للحذف' });
  }

  const index = adminMessages.findIndex((msg) => msg.email === email);
  if (index === -1) {
    return res.status(404).json({ error: 'الرسالة غير موجودة' });
  }

  adminMessages.splice(index, 1);
  res.json({ message: 'تم حذف الرسالة بنجاح' });
});

// ===== Utilities =====
// حماية بسيطة من إدخال HTML داخل الإيميل
function escapeHtml(str) {
  return String(str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

// تشغيل السيرفر
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
