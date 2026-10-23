// えこぷろ ホームページ無料診断 — 判定API
// 公開されているトップページを1回ずつ閲覧するだけの「外から見える範囲」の診断です。
// 脆弱性を突くような通信は一切行いません。

import dns from "node:dns/promises";
import net from "node:net";

// 2026年10月21日の緊急修正（CVE-2026-109618 / 109619）が入った版
const FIXED = { "8.5": 12, "8.4": 27, "8.3": 36, "8.2": 35 };

const UA = "Mozilla/5.0 (compatible; EcoproSiteCheck/1.0; +https://ecopro092.com/)";
const TIMEOUT_MS = 8000;
const MAX_BODY = 1_000_000;

// ---------- 入力チェック・SSRF対策 ----------
function normalizeHost(input) {
  let s = String(input || "").trim();
  if (!s) throw new Error("URLを入力してください");
  if (!/^https?:\/\//i.test(s)) s = "http://" + s;
  let u;
  try { u = new URL(s); } catch { throw new Error("URLの形式が正しくありません"); }
  if (u.port && !["80", "443"].includes(u.port)) throw new Error("このURLは診断できません");
  const host = u.hostname.toLowerCase();
  if (!host.includes(".") || host.endsWith(".local") || host.endsWith(".internal")) {
    throw new Error("このURLは診断できません");
  }
  return host;
}

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v = ip.toLowerCase();
  return v === "::1" || v === "::" || v.startsWith("fc") || v.startsWith("fd") ||
    v.startsWith("fe80") || v.startsWith("::ffff:");
}

async function assertPublicHost(host) {
  if (net.isIP(host)) throw new Error("IPアドレスではなくドメイン名で入力してください");
  let addrs;
  try { addrs = await dns.lookup(host, { all: true }); }
  catch { throw new Error("そのドメインは見つかりませんでした"); }
  if (!addrs.length || addrs.some((a) => isPrivateIp(a.address))) {
    throw new Error("このURLは診断できません");
  }
}

// ---------- 取得 ----------
async function fetchOnce(url) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      redirect: "manual",
      signal: ctrl.signal,
      headers: { "user-agent": UA, accept: "text/html,*/*" },
    });
    return res;
  } finally { clearTimeout(t); }
}

// 同じドメイン内のリダイレクトだけ最大5回たどる
async function fetchFollow(startUrl, host) {
  let url = startUrl;
  const chain = [];
  for (let i = 0; i < 6; i++) {
    const res = await fetchOnce(url);
    chain.push({ url, status: res.status });
    const loc = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && loc) {
      const next = new URL(loc, url);
      const nh = next.hostname.toLowerCase();
      const base = host.replace(/^www\./, "");
      if (nh !== host && nh.replace(/^www\./, "") !== base) {
        return { res, chain, finalUrl: url, offsite: next.href };
      }
      await assertPublicHost(nh);
      url = next.href;
      continue;
    }
    return { res, chain, finalUrl: url };
  }
  throw new Error("リダイレクトが多すぎます");
}

async function readBody(res) {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  while (size < MAX_BODY) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.length;
  }
  try { reader.cancel(); } catch {}
  return new TextDecoder("utf-8", { fatal: false }).decode(Buffer.concat(chunks));
}

// ---------- 判定 ----------
export function judgePhp(version) {
  const m = /^(\d+)\.(\d+)(?:\.(\d+))?/.exec(version || "");
  if (!m) return null;
  const major = +m[1], minor = +m[2], patch = m[3] !== undefined ? +m[3] : null;
  const key = `${major}.${minor}`;
  if (major < 8 || (major === 8 && minor < 2)) {
    return { level: "danger", text: `PHP ${version} はサポートが終了した古い版です。今回の修正も提供されません。` };
  }
  if (FIXED[key] === undefined) {
    return { level: "warn", text: `PHP ${version} が使われています。対象かどうかは制作会社・サーバー会社へ確認が必要です。` };
  }
  if (patch === null) {
    return { level: "warn", text: `PHP ${key} 系が使われています（細かい版は不明）。修正版 ${key}.${FIXED[key]} 以上か確認が必要です。` };
  }
  if (patch < FIXED[key]) {
    return { level: "danger", text: `PHP ${version} は今回の重大な欠陥が修正される前の版です。${key}.${FIXED[key]} 以上への更新が必要です。` };
  }
  return { level: "ok", text: `PHP ${version} は今回の修正済みの版です。` };
}

const STATIC_HOSTS = [
  { re: /netlify/i, name: "Netlify" },
  { re: /vercel/i, name: "Vercel" },
  { re: /github\.com|GitHub\.com/i, name: "GitHub Pages" },
  { re: /cloudflare pages/i, name: "Cloudflare Pages" },
];

function detectPlatform(headers, html) {
  const server = headers.get("server") || "";
  const powered = headers.get("x-powered-by") || "";
  const all = `${server} ${powered} ${headers.get("x-nf-request-id") ? "netlify" : ""} ${headers.get("x-vercel-id") ? "vercel" : ""} ${headers.get("x-github-request-id") ? "github.com" : ""}`;

  const gen = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(html)?.[1] ||
    /<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']/i.exec(html)?.[1] || "";

  if (/wp-content|wp-includes/i.test(html) || /wordpress/i.test(gen)) {
    const v = /WordPress\s*([\d.]+)/i.exec(gen)?.[1];
    return { kind: "php", name: v ? `WordPress ${v}` : "WordPress" };
  }
  if (/ec-cube/i.test(html) || /eccube/i.test(gen)) return { kind: "php", name: "EC-CUBE" };
  if (/wix\.com|wixstatic/i.test(html) || /wix/i.test(gen)) return { kind: "saas", name: "Wix" };
  if (/studio\.design|studio-cdn/i.test(html) || /studio/i.test(gen)) return { kind: "saas", name: "STUDIO" };
  if (/jimdo/i.test(html) || /jimdo/i.test(gen)) return { kind: "saas", name: "Jimdo" };
  if (/peraichi/i.test(html)) return { kind: "saas", name: "ペライチ" };
  if (/goope/i.test(html)) return { kind: "saas", name: "グーペ" };
  if (/cdn\.shopify|shopify/i.test(html)) return { kind: "saas", name: "Shopify" };
  if (/squarespace/i.test(html)) return { kind: "saas", name: "Squarespace" };
  if (/thebase\.in|base-ec/i.test(html)) return { kind: "saas", name: "BASE" };
  for (const s of STATIC_HOSTS) if (s.re.test(all)) return { kind: "static", name: s.name };
  if (/\.php(\?|"|')/i.test(html) || /php/i.test(powered)) return { kind: "php", name: "PHP（詳細不明）" };
  return { kind: "unknown", name: "判別できませんでした" };
}

async function diagnose(input) {
  const host = normalizeHost(input);
  await assertPublicHost(host);

  const items = [];
  let main = null;
  let httpsOk = false;
  let httpsError = null;

  // 1) https で開けるか
  try {
    const r = await fetchFollow(`https://${host}/`, host);
    if (r.offsite) {
      items.push({ level: "info", title: "別のサイトへ転送", text: `このアドレスは ${new URL(r.offsite).hostname} へ転送されています。転送先のURLで診断し直してください。` });
    }
    if (new URL(r.finalUrl).protocol === "https:") { httpsOk = true; main = r; }
    else { main = r; }
  } catch (e) {
    httpsError = e;
  }

  // 2) http から https へ自動で切り替わるか
  let httpRedirects = null;
  try {
    const r = await fetchFollow(`http://${host}/`, host);
    httpRedirects = new URL(r.finalUrl).protocol === "https:";
    if (!main) main = r;
  } catch {}

  if (!main) throw new Error("サイトに接続できませんでした。URLをご確認ください");

  if (httpsOk) {
    items.push({ level: "ok", title: "通信の暗号化（https）", text: "鍵マーク付きの安全な通信に対応しています。" });
    if (httpRedirects === false) {
      items.push({ level: "warn", title: "http のまま開ける", text: "http で開いた場合に https へ自動で切り替わりません。お客様が暗号化なしで閲覧する場合があります。" });
    }
  } else {
    items.push({ level: "danger", title: "通信の暗号化（https）", text: "鍵マーク（https）に対応していません。お問い合わせ内容などが暗号化されずに送られ、ブラウザに「保護されていない通信」と表示されます。長く手入れされていないサイトでよく見られる状態です。" });
  }

  const html = await readBody(main.res);
  const h = main.res.headers;
  const platform = detectPlatform(h, html);

  // 3) PHPの版
  const powered = h.get("x-powered-by") || "";
  const server = h.get("server") || "";
  const phpVer = /PHP\/([\d.]+)/i.exec(powered)?.[1] || /PHP\/([\d.]+)/i.exec(server)?.[1];
  const phpJudge = judgePhp(phpVer);

  if (platform.kind === "static") {
    items.push({ level: "ok", title: "PHPの重大な欠陥（2026年10月）", text: `${platform.name} で公開されたサイトで、サーバー側でPHPが動いていないため今回の件の影響はありません。` });
  } else if (platform.kind === "saas") {
    items.push({ level: "ok", title: "PHPの重大な欠陥（2026年10月）", text: `${platform.name} で作られたサイトです。サーバーの管理は ${platform.name} 側が行うため、基本的に御社での対応は不要です。` });
  } else if (phpJudge) {
    items.push({ level: phpJudge.level, title: "PHPの重大な欠陥（2026年10月）", text: phpJudge.text });
  } else if (platform.kind === "php") {
    items.push({ level: "warn", title: "PHPの重大な欠陥（2026年10月）", text: `${platform.name}で動いています。PHPが使われているため今回の件の対象になる可能性があります。外からは版が分からないため、サーバー側で更新済みかの確認が必要です。` });
  } else {
    items.push({ level: "warn", title: "PHPの重大な欠陥（2026年10月）", text: "外から見える情報では、PHPを使っているか判別できませんでした。念のため制作会社・サーバー会社へ確認をおすすめします。" });
  }

  // 4) 版情報が外から見えてしまっている
  if (phpVer) {
    items.push({ level: "warn", title: "システム情報が丸見え", text: `サーバーが「PHP ${phpVer}」を使っていることを外部に公開しています。攻撃者が狙いを付けやすくなるため、非表示にする設定がおすすめです。` });
  }
  if (platform.kind === "php" && /WordPress \d/.test(platform.name)) {
    items.push({ level: "warn", title: "WordPressの版が丸見え", text: `${platform.name} を使っていることがページ内に表示されています。古い版のままだと狙われやすくなります。` });
  }

  const order = { danger: 3, warn: 2, info: 1, ok: 0 };
  const worst = items.reduce((m, i) => (order[i.level] > order[m] ? i.level : m), "ok");
  const verdict = worst === "danger" ? "danger" : worst === "warn" ? "warn" : "ok";

  return {
    host,
    checkedAt: new Date().toISOString(),
    platform: platform.name,
    verdict,
    items,
  };
}

export default async (req) => {
  const json = (obj, status = 200) => new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
  if (req.method !== "POST") return json({ error: "POSTで送信してください" }, 405);
  let body;
  try { body = await req.json(); } catch { return json({ error: "送信内容が読み取れません" }, 400); }
  try {
    return json(await diagnose(body.url));
  } catch (e) {
    return json({ error: e.message || "診断できませんでした" }, 400);
  }
};

export const config = { path: "/api/check" };
