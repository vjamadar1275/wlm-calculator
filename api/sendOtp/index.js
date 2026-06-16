const crypto = require('crypto');
const sgMail = require('@sendgrid/mail');

const ALLOWED_DOMAINS = (process.env.ALLOWED_DOMAINS || 'idrica.com,xylem.com')
  .split(',').map(d => d.trim().toLowerCase());

function hmac(data) {
  return crypto.createHmac('sha256', process.env.SESSION_SECRET).update(data).digest('hex');
}

module.exports = async function (context, req) {
  if (req.method !== 'POST') {
    context.res = { status: 405, body: { error: 'Method not allowed' } };
    return;
  }

  const email = (req.body?.email || '').trim().toLowerCase();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    context.res = { status: 400, body: { error: 'Invalid email address.' } };
    return;
  }

  const domain = email.split('@')[1];
  if (!ALLOWED_DOMAINS.includes(domain)) {
    context.res = {
      status: 403,
      body: { error: `Access is restricted to ${ALLOWED_DOMAINS.map(d => '@' + d).join(' and ')} addresses.` }
    };
    return;
  }

  // Generate 6-digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  // Stateless challenge: HMAC(email:otp:time_window) — no DB needed
  const win = Math.floor(Date.now() / (10 * 60 * 1000)); // 10-min rolling window
  const challenge = hmac(`${email}:${otp}:${win}`);

  // Send via SendGrid
  try {
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
    await sgMail.send({
      to: email,
      from: { email: process.env.SENDGRID_FROM_EMAIL, name: 'WLM Calculator' },
      subject: 'Your WLM Calculator Access Code',
      text: `Your one-time access code is: ${otp}\n\nThis code expires in 10 minutes.\n\nIf you did not request this, please ignore this email.`,
      html: `
<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;">
  <div style="background:#0f3460;color:#fff;padding:20px 24px;border-radius:8px 8px 0 0;">
    <h2 style="margin:0;font-size:18px;">WLM Infrastructure Calculator</h2>
    <p style="margin:4px 0 0;font-size:12px;opacity:0.75;">One-Time Access Code</p>
  </div>
  <div style="background:#fff;border:1px solid #d0dae8;border-top:none;padding:28px 24px;border-radius:0 0 8px 8px;">
    <p style="color:#1e2a3a;margin:0 0 20px;">Use the code below to sign in:</p>
    <div style="background:#f4f7fb;border-radius:8px;padding:20px;text-align:center;letter-spacing:10px;font-size:34px;font-weight:700;color:#0f3460;margin-bottom:20px;">${otp}</div>
    <p style="color:#6b7c93;font-size:13px;margin:0;">This code expires in <strong>10 minutes</strong>.<br>If you did not request access, please ignore this email.</p>
  </div>
</div>`
    });
  } catch (err) {
    context.log.error('SendGrid error:', err.response?.body || err.message);
    context.res = { status: 500, body: { error: 'Failed to send email. Please try again shortly.' } };
    return;
  }

  context.res = {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    body: { challenge }
  };
};
