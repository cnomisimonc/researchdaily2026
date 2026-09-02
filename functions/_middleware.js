// Research Daily — shared-password gate (HTTP Basic Auth).
//
// Runs in front of EVERY request to the Pages project, including /docs/*.pdf.
//
// Pages → Settings → Variables and secrets (Production):
//   SITE_PASSWORD  required — the shared password
//   SITE_USER      optional — if unset, ANY username is accepted
//
// Values are trimmed, so a stray space or newline pasted into the dashboard
// field will not lock you out. If SITE_PASSWORD is missing the site fails
// closed with a 503 rather than serving unprotected.

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Browsers differ on how they encode non-ASCII credentials. Try UTF-8 first,
// fall back to the raw latin1 bytes, and accept either.
function decodeCandidates(b64) {
  let raw;
  try {
    raw = atob(b64);
  } catch {
    return [];
  }
  const out = [raw];
  try {
    const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
    const utf8 = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (utf8 !== raw) out.push(utf8);
  } catch {
    /* not valid UTF-8; latin1 reading stands */
  }
  return out;
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
  const wantPass = (env.SITE_PASSWORD || "").trim();
  const wantUser = (env.SITE_USER || "").trim(); // empty => any username

  if (!wantPass) {
    return new Response("Site auth is not configured.", {
      status: 503,
      headers: { "Cache-Control": "no-store" },
    });
  }

  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Basic ")) {
    return new Response("Authentication required.", CHALLENGE);
  }

  let ok = false;
  for (const decoded of decodeCandidates(header.slice(6))) {
    const sep = decoded.indexOf(":");
    if (sep === -1) continue;
    const gotUser = decoded.slice(0, sep).trim();
    const gotPass = decoded.slice(sep + 1); // never trimmed — spaces may be real
    const userOk = wantUser === "" || safeEqual(gotUser, wantUser);
    if (userOk && (safeEqual(gotPass, wantPass) || safeEqual(gotPass.trim(), wantPass))) {
      ok = true;
      break;
    }
  }

  if (!ok) return new Response("Authentication required.", CHALLENGE);

  const response = await next();
  const out = new Response(response.body, response);
  out.headers.set("Cache-Control", "private, no-store");
  return out;
};
