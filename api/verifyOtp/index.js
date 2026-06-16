const crypto = require('crypto');

function hmac(data) {
  return crypto.createHmac('sha256', process.env.SESSION_SECRET).update(data).digest('hex');
}

function verifyChallenge(email, otp, challenge) {
  const now = Date.now();
  // Accept current and previous 10-min window (grace for clock skew)
  const windows = [
    Math.floor(now / (10 * 60 * 1000)),
    Math.floor(now / (10 * 60 * 1000)) - 1
  ];
  return windows.some(w => hmac(`${email}:${otp}:${w}`) === challenge);
}

function createSession(email) {
  const expiry = Date.now() + 8 * 60 * 60 * 1000; // 8-hour session
  const sig = hmac(`${email}:${expiry}`);
  return Buffer.from(JSON.stringify({ email, expiry, sig })).toString('base64url');
}

module.exports = async function (context, req) {
  if (req.method !== 'POST') {
    context.res = { status: 405, body: { error: 'Method not allowed' } };
    return;
  }

  const { email, otp, challenge } = req.body || {};
  if (!email || !otp || !challenge) {
    context.res = { status: 400, body: { error: 'Missing required fields.' } };
    return;
  }

  const cleanEmail = email.trim().toLowerCase();
  const cleanOtp   = String(otp).replace(/\D/g, '');

  if (!verifyChallenge(cleanEmail, cleanOtp, challenge)) {
    context.res = { status: 401, body: { error: 'Invalid or expired code. Please request a new one.' } };
    return;
  }

  const token = createSession(cleanEmail);

  context.res = {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': `wlm_session=${token}; HttpOnly; Secure; SameSite=Strict; Max-Age=28800; Path=/`
    },
    body: { ok: true, email: cleanEmail }
  };
};
