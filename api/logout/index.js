module.exports = async function (context, req) {
  context.res = {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': 'wlm_session=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/'
    },
    body: { ok: true }
  };
};
