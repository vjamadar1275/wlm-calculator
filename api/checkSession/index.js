const crypto = require('crypto');

function hmac(data) {
  return crypto.createHmac('sha256', process.env.SESSION_SECRET).update(data).digest('hex');
}

function verifySession(token) {
  try {
    const { email, expiry, sig } = JSON.parse(Buffer.from(token, 'base64url').toString());
    if (!email || !expiry || !sig) return null;
    if (Date.now() > expiry) return null;
    if (hmac(`${email}:${expiry}`) !== sig) return null;
    return email;
  } catch {
    return null;
  }
}

module.exports = async function (context, req) {
  const cookies = req.headers['cookie'] || '';
  const match   = cookies.match(/wlm_session=([^;]+)/);
  const token   = match ? decodeURIComponent(match[1]) : null;

  if (!token) {
    context.res = { status: 401, body: { error: 'Not authenticated' } };
    return;
  }

  const email = verifySession(token);
  if (!email) {
    context.res = {
      status: 401,
      headers: { 'Set-Cookie': 'wlm_session=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/' },
      body: { error: 'Session expired. Please sign in again.' }
    };
    return;
  }

  context.res = {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    body: { email }
  };
};
