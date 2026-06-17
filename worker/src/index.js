/**
 * 秘密關係 OST — Cloudflare Worker
 * 1. POST /stripe-webhook  Stripe 付款完成 → 產生兌換碼 → 存 KV → 用 Resend 寄信
 * 2. POST /verify          前端解鎖頁呼叫，驗證 email + 兌換碼
 * 3. GET  /track           已解鎖的使用者拿付費曲目（03~21）的音檔內容，從 R2 讀取
 */

// 03~21 首付費曲目檔名白名單（要跟 index.html 的 TRACKS 完全一致）
const PROTECTED_FILES = new Set([
  "03_假裝教你戀愛.mp3",
  "04_越界以後.mp3",
  "05_Sometimes_I_See_You.mp3",
  "06_藍色的暗戀.mp3",
  "07_晴天裡擁抱你.mp3",
  "08_心跳先說了祕密.mp3",
  "09_喜歡你的回音.mp3",
  "10_電影院沒有第三個人.mp3",
  "11_如果你也害怕.mp3",
  "12_把喜歡藏進音樂盒.mp3",
  "13_戀愛練習題.mp3",
  "14_幼稚鬼決鬥.mp3",
  "15_喜歡你這件小事.mp3",
  "16_靠近你的安全距離.mp3",
  "17_晴天裡，我終於懂了.mp3",
  "18_不能被發現的心意.mp3",
  "19_拓晞爭吵，你為什麼不懂.mp3",
  "20_等待阿拓.mp3",
  "21_最終的告白，我喜歡的一直是你.mp3",
]);

function corsHeaders(request, env) {
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
  const origin = request.headers.get("Origin") || "";
  const allow = allowed.includes(origin) ? origin : (allowed[0] || "*");
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
  };
}

function json(data, status, request, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders(request, env) },
  });
}

function genCode() {
  // 避開容易混淆的字元 0/O、1/I
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  let s = "";
  for (let i = 0; i < 8; i++) s += chars[bytes[i] % chars.length];
  return `SLOV-${s.slice(0, 4)}-${s.slice(4, 8)}`;
}

async function verifyStripeSignature(body, sigHeader, secret) {
  if (!sigHeader) return false;
  const parts = {};
  for (const kv of sigHeader.split(",")) {
    const idx = kv.indexOf("=");
    if (idx === -1) continue;
    parts[kv.slice(0, idx)] = kv.slice(idx + 1);
  }
  if (!parts.t || !parts.v1) return false;
  const signedPayload = `${parts.t}.${body}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signedPayload));
  const expectedHex = [...new Uint8Array(sigBuf)].map((b) => b.toString(16).padStart(2, "0")).join("");
  // constant-time-ish compare
  if (expectedHex.length !== parts.v1.length) return false;
  let diff = 0;
  for (let i = 0; i < expectedHex.length; i++) diff |= expectedHex.charCodeAt(i) ^ parts.v1.charCodeAt(i);
  return diff === 0;
}

async function sendRedeemEmail(env, email, code, product) {
  const productName = product === "599" ? "秘密關係 OST 典藏版（+WAV）" : "秘密關係 OST 數位專輯";
  const html = `
    <div style="font-family:'Helvetica Neue',Arial,sans-serif;padding:32px;color:#3d3d44;background:#faf7f2">
      <h2 style="color:#3d3d44">感謝購買《秘密關係》OST</h2>
      <p>您購買的方案：<b>${productName}</b></p>
      <p>請回到 app 的「解鎖」頁，輸入以下資訊：</p>
      <p style="margin:4px 0">Email：${email}</p>
      <p style="font-size:22px;font-weight:bold;letter-spacing:2px;color:#6b8fc7;margin:8px 0">兌換碼：${code}</p>
      <p style="font-size:13px;color:#9a93a8">請保留這封信，之後在其他裝置上也能用這組 Email + 兌換碼解鎖。</p>
    </div>`;
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: env.RESEND_FROM || "OST <onboarding@resend.dev>",
      to: email,
      subject: "《秘密關係》OST 兌換碼",
      html,
    }),
  });
  if (!res.ok) {
    console.log("Resend send failed", res.status, await res.text());
  }
}

async function handleStripeWebhook(request, env) {
  const body = await request.text();
  const sig = request.headers.get("stripe-signature");
  const ok = await verifyStripeSignature(body, sig, env.STRIPE_WEBHOOK_SECRET);
  if (!ok) return new Response("invalid signature", { status: 400 });

  let event;
  try {
    event = JSON.parse(body);
  } catch {
    return new Response("bad json", { status: 400 });
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const email = session.customer_details?.email || session.customer_email;
    if (email) {
      // TWD 在 Stripe 是 zero-decimal 幣別，amount_total 299 就是 NT$299
      const amount = session.amount_total || 0;
      const product = amount >= 599 ? "599" : "299";
      const code = genCode();
      await env.CODES.put(code, JSON.stringify({ email, product, ts: Date.now() }));
      await sendRedeemEmail(env, email, code, product);
    }
  }
  return new Response("ok", { status: 200 });
}

async function handleVerify(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, message: "bad request" }, 400, request, env);
  }
  const email = (body.email || "").trim().toLowerCase();
  const code = (body.code || "").trim().toUpperCase();
  if (!email || !code) return json({ ok: false, message: "請輸入 email 和兌換碼" }, 400, request, env);

  const rec = await env.CODES.get(code);
  if (!rec) return json({ ok: false, message: "兌換碼或 email 不正確" }, 404, request, env);

  const data = JSON.parse(rec);
  if ((data.email || "").trim().toLowerCase() !== email) {
    return json({ ok: false, message: "兌換碼或 email 不正確" }, 403, request, env);
  }
  return json({ ok: true, product: data.product }, 200, request, env);
}

async function handleTrack(request, env, url) {
  const file = url.searchParams.get("file") || "";
  const email = (url.searchParams.get("email") || "").trim().toLowerCase();
  const code = (url.searchParams.get("code") || "").trim().toUpperCase();

  if (!PROTECTED_FILES.has(file)) {
    return new Response("not found", { status: 404, headers: corsHeaders(request, env) });
  }
  if (!email || !code) {
    return new Response("unauthorized", { status: 401, headers: corsHeaders(request, env) });
  }
  const rec = await env.CODES.get(code);
  if (!rec) return new Response("unauthorized", { status: 401, headers: corsHeaders(request, env) });
  const data = JSON.parse(rec);
  if ((data.email || "").trim().toLowerCase() !== email) {
    return new Response("unauthorized", { status: 401, headers: corsHeaders(request, env) });
  }

  const obj = await env.AUDIO.get(`OST/${file}`);
  if (!obj) return new Response("file not found", { status: 404, headers: corsHeaders(request, env) });

  const headers = new Headers(corsHeaders(request, env));
  obj.writeHttpMetadata(headers);
  headers.set("etag", obj.httpEtag);
  if (!headers.get("content-type")) headers.set("content-type", "audio/mpeg");
  headers.set("cache-control", "private, max-age=0, must-revalidate");
  return new Response(obj.body, { headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(request, env) });
    }

    if (url.pathname === "/stripe-webhook" && request.method === "POST") {
      return handleStripeWebhook(request, env);
    }
    if (url.pathname === "/verify" && request.method === "POST") {
      return handleVerify(request, env);
    }
    if (url.pathname === "/track" && request.method === "GET") {
      return handleTrack(request, env, url);
    }
    return json({ ok: false, message: "not found" }, 404, request, env);
  },
};
