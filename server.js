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
const safeMessageHtml = escapeHtml(message).replace(/\n/g, '<br/>');
const previewText = 'تم إرسال نتيجة/رسالة من lab-results';

await transporter.sendMail({
  from: `"lab-results (معمل چون)" <${process.env.SMTP_USER}>`,
  to: email,
  subject: 'lab-results (معمل چون)',
  text: message, // خلي الـ plain text موجود لتحسين التوافق
  html: `<!doctype html>
<html lang="ar" dir="rtl">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>lab-results</title>
  </head>
  <body style="margin:0;padding:0;background:#f6f7fb;">
    <!-- Preheader (بيظهر جنب العنوان في بعض التطبيقات) -->
    <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">
      ${previewText}
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f6f7fb;padding:24px 12px;">
      <tr>
        <td align="center">
          <!-- Container -->
          <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="width:600px;max-width:600px;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 6px 24px rgba(20,20,43,.08);">
            <!-- Header -->
            <tr>
              <td style="background:#111827;padding:18px 22px;">
                <div style="font-family:Arial,Helvetica,sans-serif;font-size:18px;line-height:1.4;color:#ffffff;font-weight:700;">
                  lab-results <span style="font-weight:400;opacity:.85;">(معمل چون)</span>
                </div>
                <div style="font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:1.6;color:#cbd5e1;margin-top:6px;">
                  رسالة تلقائية — برجاء عدم الرد على هذا البريد
                </div>
              </td>
            </tr>

            <!-- Body -->
            <tr>
              <td style="padding:22px;">
                <div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.9;color:#111827;">
                  <div style="font-size:16px;font-weight:700;margin-bottom:10px;">مرحبًا،</div>

                  <div style="background:#f3f4f6;border:1px solid #e5e7eb;border-radius:12px;padding:14px 14px;">
                    <div style="font-size:12px;color:#6b7280;margin-bottom:8px;">نص الرسالة:</div>
                    <div style="font-size:14px;color:#111827;">
                      ${safeMessageHtml}
                    </div>
                  </div>

                  <div style="margin-top:16px;font-size:12px;color:#6b7280;">
                    إذا لم تكن تتوقع هذه الرسالة، يمكنك تجاهلها.
                  </div>
                </div>
              </td>
            </tr>

            <!-- Footer -->
            <tr>
              <td style="padding:16px 22px;background:#f9fafb;border-top:1px solid #eef2f7;">
                <div style="font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:1.7;color:#6b7280;">
                  © ${new Date().getFullYear()} lab-results — جميع الحقوق محفوظة
                </div>
              </td>
            </tr>
          </table>

          <!-- Spacer -->
          <div style="height:14px;"></div>

          <div style="font-family:Arial,Helvetica,sans-serif;font-size:11px;color:#9ca3af;">
            تم الإرسال عبر Nodemailer
          </div>
        </td>
      </tr>
    </table>
  </body>
</html>`
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
