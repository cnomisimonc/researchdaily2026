// Research Daily — shared-password gate (HTTP Basic Auth).
//
// Runs in front of EVERY request to the Pages project, including /docs/*.pdf.
// Credentials come from Pages → Settings → Variables and secrets:
//   SITE_USER      e.g.  research
//   SITE_PASSWORD  the shared password
// Set both as *Secrets* (encrypted), on the Production environment.
//
// If either variable is missing the site fails closed (503) rather than
// silently serving unprotected — safer than the alternative.

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

const CHALLENGE = {
  status: 401,
  headers: {
    "WWW-Authenticate": 'Basic realm="Research Daily", charset="UTF-8"',
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "no-store",
  },
};

export const onRequest = async ({ request, env, next }) => {
  const user = env.SITE_USER;
  const pass = env.SITE_PASSWORD;

  if (!user || !pass) {
    return new Response("Site auth is not configured.", {
      status: 503,
      headers: { "Cache-Control": "no-store" },
    });
  }

  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Basic ")) {
    return new Response("Authentication required.", CHALLENGE);
  }

  let decoded;
  try {
    decoded = atob(header.slice(6));
  } catch {
    return new Response("Authentication required.", CHALLENGE);
  }

  const sep = decoded.indexOf(":");
  const gotUser = sep === -1 ? decoded : decoded.slice(0, sep);
  const gotPass = sep === -1 ? "" : decoded.slice(sep + 1);

  if (!timingSafeEqual(gotUser, user) || !timingSafeEqual(gotPass, pass)) {
    return new Response("Authentication required.", CHALLENGE);
  }

  const response = await next();
  // Keep authenticated pages out of shared/CDN caches.
  const out = new Response(response.body, response);
  out.headers.set("Cache-Control", "private, no-store");
  return out;
};
