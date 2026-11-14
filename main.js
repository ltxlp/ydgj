/**
 * 野果短剧 Worker（Deno Deploy / Cloudflare 通用）
 *
 * 注意：yeguodj 系域名对 Cloudflare 出口 403，请用 Deno Deploy 部署。
 *
 * 网页/TVBox：
 *   /home  /category  /detail  /play  /search  /proxy  /debug
 * CarPlay / IPTV：
 *   /live.m3u   /live.m3u?pages=3&eps=10
 *   /play?id=vid:集数::&redirect=1
 */

// yeguodj.com 对 CF Worker 会 403（administrative rules），优先备用域
const SITE_CANDIDATES = [
  "https://ygdj1.com",
  "https://www.yeguodj.com",
  "https://yeguodj.com"
];
let SITE = SITE_CANDIDATES[0];
let API_BASE = SITE + "/api.php";
const UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";

function setSite(host) {
  SITE = String(host || SITE_CANDIDATES[0]).replace(/\/+$/, "");
  API_BASE = SITE + "/api.php";
}

// AES 密钥（十六进制字符串 → 16 字节）
const API_KEY   = new TextEncoder().encode("2acf7e91e9864673");
const API_IV    = new TextEncoder().encode("1c29882d3ddfcfd6");
const MEDIA_KEY = new TextEncoder().encode("f5d965df75336270");
const MEDIA_IV  = new TextEncoder().encode("97b60394abc2fbe1");

const API_PATHS = new Set(["/home", "/category", "/detail", "/play", "/search", "/proxy", "/debug", "/live.m3u", "/m3u"]);
const M3U_PAGES_PER_CAT = 3;       // 每个分类抓几页
const M3U_DEFAULT_EPS   = 8;       // 列表无集数时默认展开集数
const M3U_MAX_EPS       = 20;      // 单部最多展开多少集

// ============================================================
// 分类表
// ============================================================
const CLASSES = [
  { type_id: "explore",    type_name: "发现" },
  { type_id: "rank",       type_name: "排行榜" },
  { type_id: "dushi",      type_name: "都市" },
  { type_id: "xiandai",    type_name: "现代" },
  { type_id: "xiaoyuan",   type_name: "校园" },
  { type_id: "gudai",      type_name: "古代" },
  { type_id: "xiangcun",   type_name: "乡村" },
  { type_id: "zhichang",   type_name: "职场" },
  { type_id: "chongsheng", type_name: "重生" },
  { type_id: "chuanyue",   type_name: "穿越" },
  { type_id: "xitong",     type_name: "系统" },
  { type_id: "nixi",       type_name: "逆袭" },
  { type_id: "mogai",      type_name: "魔改" },
];

const BG_MAP = {
  dushi: 40, xiandai: 39, xiaoyuan: 47,
  gudai: 41, xiangcun: 42, zhichang: 44,
};

const SETTING_MAP = {
  chongsheng: 26, chuanyue: 27, xitong: 28,
  nixi: 53, mogai: 56,
};

// ============================================================
// 工具函数
// ============================================================

function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*"
    }
  });
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function aesCbcDecrypt(cipherBytes, keyBytes, ivBytes) {
  try {
    const key = await crypto.subtle.importKey(
      "raw", keyBytes, { name: "AES-CBC" }, false, ["decrypt"]
    );
    const dec = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: ivBytes }, key, cipherBytes
    );
    return new Uint8Array(dec);
  } catch (e) {
    return null;
  }
}

function detectMime(b) {
  if (!b || b.length < 4) return null;
  if (b[0] === 0xFF && b[1] === 0xD8) return "image/jpeg";
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47) return "image/png";
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return "image/gif";
  if (b.length >= 12 &&
      b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
      b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return "image/webp";
  return null;
}

function proxyImage(picUrl, origin) {
  if (!picUrl) return "";
  return `${origin}/proxy?url=${encodeURIComponent(picUrl)}`;
}

// ============================================================
// 后端 API 请求（POST + 自动解密 data）
// ============================================================

function stripPkcs7(bytes) {
  if (!bytes || !bytes.length) return bytes;
  const pad = bytes[bytes.length - 1];
  if (pad > 0 && pad <= 16 && bytes.length >= pad) {
    let ok = true;
    for (let i = 0; i < pad; i++) if (bytes[bytes.length - 1 - i] !== pad) { ok = false; break; }
    if (ok) return bytes.slice(0, bytes.length - pad);
  }
  return bytes;
}

async function apiPostOnce(site, path, body) {
  const apiBase = site.replace(/\/+$/, "") + "/api.php";
  const url = apiBase + path;
  const meta = { url, site, status: 0, bytes: 0, err: "", keys: [] };
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: {
        "User-Agent": UA,
        "Referer": site + "/",
        "Origin": site,
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json;charset=UTF-8",
        "Accept-Language": "zh-CN,zh;q=0.9"
      },
      body: JSON.stringify(body || {}),
      redirect: "follow"
    });
    meta.status = r.status;
    const text = await r.text();
    meta.bytes = text.length;
    meta.head = String(text).slice(0, 160);
    if (!r.ok) {
      meta.err = "http " + r.status;
      return { ok: false, meta, data: null };
    }
    let d;
    try { d = JSON.parse(text); } catch (e) {
      meta.err = "json parse fail";
      return { ok: false, meta, data: null };
    }

    for (let round = 0; round < 2; round++) {
      const dataVal = d && d.data;
      if (typeof dataVal === "string" && dataVal.length > 20) {
        try {
          const cipher = base64ToBytes(dataVal);
          let dec = await aesCbcDecrypt(cipher, API_KEY, API_IV);
          if (!dec) { meta.err = "decrypt null r" + round; break; }
          dec = stripPkcs7(dec);
          let decText = new TextDecoder("utf-8", { fatal: false }).decode(dec).replace(/\x00+$/g, "").trim();
          const lastBrace = Math.max(decText.lastIndexOf("}"), decText.lastIndexOf("]"));
          if (lastBrace > 0) decText = decText.slice(0, lastBrace + 1);
          d = JSON.parse(decText);
          meta["dec" + round] = "ok len=" + decText.length;
        } catch (e) {
          meta.err = "decrypt fail: " + (e && e.message ? e.message : e);
          return { ok: false, meta, data: null };
        }
      } else if (dataVal && typeof dataVal === "object") {
        break;
      } else break;
    }

    meta.keys = d && typeof d === "object" ? Object.keys(d) : [];
    return { ok: true, meta, data: d };
  } catch (e) {
    meta.err = String(e && e.message ? e.message : e);
    return { ok: false, meta, data: null };
  }
}

async function apiPost(path, body, debug = false) {
  // 当前 SITE 优先，失败再轮询备用域（解决 yeguodj.com 对 CF Worker 403）
  const tried = [];
  const hosts = [SITE, ...SITE_CANDIDATES.filter(h => h !== SITE)];
  for (const host of hosts) {
    const r = await apiPostOnce(host, path, body);
    tried.push(r.meta);
    if (r.ok && r.data) {
      if (host !== SITE) setSite(host);
      if (debug) {
        try { r.data.__meta = r.meta; r.data.__tried = tried; } catch (e) {}
      }
      return r.data;
    }
  }
  if (debug) return { __meta: tried[tried.length - 1] || {}, __tried: tried };
  return {};
}

function unwrap(d) {
  if (!d) return {};
  let x = d;
  // 最多剥 3 层 data
  for (let i = 0; i < 3; i++) {
    if (x && typeof x === "object" && !Array.isArray(x) && x.data !== undefined && x.data !== null) {
      // 若 data 仍是加密字符串则停
      if (typeof x.data === "string") break;
      x = x.data;
    } else break;
  }
  return x;
}

// ============================================================
// 视频对象
// ============================================================

function toVod(it, origin) {
  if (!it) return null;
  let vid = it.video_id !== undefined && it.video_id !== null ? it.video_id : (it.id || "");
  vid = String(vid).trim();
  if (!vid) return null;

  const title = String(it.title || it.video_title || it.name || vid).trim();
  const rawPic = String(it.cover || it.cover_img || it.pic || "").trim();
  const ep = it.episode_count || it.episodes || it.total_serial || it.serial_count || "";
  let remark = String(it.update_status || it.serialize_status_text || it.app_badge?.text || "").trim();
  if (!remark && ep) remark = `更新至${ep}集`;

  return {
    vod_id: vid,
    vod_name: title,
    vod_pic: proxyImage(rawPic, origin),
    vod_remarks: remark,
    _epHint: parseInt(ep, 10) || 0,
    _rawPic: rawPic
  };
}

function listFromPayload(d, origin) {
  const inner = unwrap(d);
  let arr = [];
  if (Array.isArray(inner)) {
    arr = inner;
  } else if (inner && typeof inner === "object") {
    arr = inner.list || inner.top_list || [];
    // 再往下剥一层（有的接口 data.data.list）
    if (!arr.length && inner.data && typeof inner.data === "object") {
      arr = inner.data.list || inner.data.top_list || [];
      if (!arr.length && Array.isArray(inner.data)) arr = inner.data;
    }
    // modules.list 里可能还有
    if (!arr.length && Array.isArray(inner.modules)) {
      for (const m of inner.modules) {
        if (m && Array.isArray(m.list)) arr = arr.concat(m.list);
      }
    }
    if (!arr.length && inner.modules && Array.isArray(inner.modules.list)) {
      for (const m of inner.modules.list) {
        if (m && Array.isArray(m.list)) arr = arr.concat(m.list);
        else if (m && (m.video_id || m.id)) arr.push(m);
      }
    }
  }
  const out = [];
  for (const it of arr) {
    const v = toVod(it, origin);
    if (v) out.push(v);
  }
  return out;
}

// ============================================================
// /home 首页
// ============================================================

async function handleHome(url) {
  const origin = url.origin;
  let list = [];

  // 1) 首页接口
  try {
    const d = await apiPost("/api/home/homePage", {});
    const inner = unwrap(d);
    const combined = [];
    if (inner && typeof inner === "object" && !Array.isArray(inner)) {
      if (Array.isArray(inner.top_list)) combined.push(...inner.top_list);
      const mods = (inner.modules && inner.modules.list) || [];
      for (const mod of mods) {
        if (mod && Array.isArray(mod.list)) combined.push(...mod.list);
        else if (mod && (mod.video_id || mod.id)) combined.push(mod);
      }
      if (Array.isArray(inner.list)) combined.push(...inner.list);
    } else if (Array.isArray(inner)) {
      combined.push(...inner);
    }
    const seen = new Set();
    for (const it of combined) {
      const v = toVod(it, origin);
      if (v && !seen.has(v.vod_id)) { seen.add(v.vod_id); list.push(v); }
    }
  } catch (e) {
    console.log("[home]", e.message || e);
  }

  // 2) 首页空则用发现列表兜底（这是空壳的主因）
  if (!list.length) {
    try {
      const d2 = await apiPost("/api/theater/exploreList", { page: 1, limit: 30 });
      list = listFromPayload(d2, origin);
    } catch (e) {
      console.log("[home fallback]", e.message || e);
    }
  }

  return jsonResp({ class: CLASSES, list: list.slice(0, 48) });
}

// ============================================================
// /category 分类列表
// ============================================================

async function handleCategory(url) {
  const origin = url.origin;
  const tid = url.searchParams.get("tid") || "explore";
  const pg = parseInt(url.searchParams.get("pg") || "1");

  let d;
  if (tid === "rank") {
    d = await apiPost("/api/theater/videoRank", { page: pg, limit: 24 });
  } else if (BG_MAP[tid] !== undefined) {
    d = await apiPost("/api/theater/exploreList", { page: pg, limit: 24, background: BG_MAP[tid] });
  } else if (SETTING_MAP[tid] !== undefined) {
    d = await apiPost("/api/theater/exploreList", { page: pg, limit: 24, setting: SETTING_MAP[tid] });
  } else {
    d = await apiPost("/api/theater/exploreList", { page: pg, limit: 24 });
  }

  const list = listFromPayload(d, origin);
  return jsonResp({
    list,
    page: pg,
    pagecount: list.length >= 24 ? pg + 1 : pg,
    limit: 24,
    total: 9999
  });
}

// ============================================================
// /detail 详情 —— 关键修改：把剧集真实 ID 编进 playId
// ============================================================

async function handleDetail(url) {
  const origin = url.origin;
  const id = url.searchParams.get("id") || "";
  if (!id) return jsonResp({ list: [] });

  const vid = /^\d+$/.test(id) ? parseInt(id) : id;
  const d = await apiPost("/api/playlet/detail", { video_id: vid });
  let info = unwrap(d);

  if (info && typeof info === "object" && info.video_id === undefined && info.data && typeof info.data === "object") {
    info = info.data;
  }
  if (!info || typeof info !== "object") info = {};

  const title = String(info.title || id).trim();
  const rawPic = String(info.cover || info.cover_img || "").trim();
  const rawDesc = String(info.description || info.intro || "").trim();

  const eps = Array.isArray(info.episodes) ? info.episodes : [];
  const playUrls = [];

  if (eps.length > 0) {
    eps.forEach((ep, idx) => {
      // 集数序号
      const n = String(
        ep.sort !== undefined ? ep.sort :
        (ep.episode !== undefined ? ep.episode :
        (ep.index !== undefined ? ep.index : (idx + 1)))
      ).trim();

      // 剧集真实 ID（不是视频ID）——这是能切换到不同集的关键
      let realId = "";
      if (ep.id !== undefined && ep.id !== null) realId = String(ep.id);
      else if (ep.episode_id !== undefined && ep.episode_id !== null) realId = String(ep.episode_id);
      else if (ep.video_episode_id !== undefined && ep.video_episode_id !== null) realId = String(ep.video_episode_id);
      else if (ep.nid !== undefined && ep.nid !== null) realId = String(ep.nid);

      // 有的站点剧集对象里本身就带 video_url，直接缓存
      const epUrl = String(ep.video_url || ep.url || ep.play_url || "").trim();

      let tName = String(ep.title || `第${n}集`).trim();
      tName = tName.replace(/\$/g, "").replace(/#/g, "");

      // playId 格式：videoId:集数:剧集真实ID:剧集URL（后两个可能为空）
      const parts = [id, n, realId, epUrl ? encodeURIComponent(epUrl) : ""];
      playUrls.push(`${tName}$${parts.join(":")}`);
    });
  } else {
    const total = parseInt(info.episode_count || info.total_serial || 1);
    const n = Math.max(1, total);
    for (let i = 1; i <= n; i++) {
      playUrls.push(`第${i}集$${id}:${i}::`);
    }
  }

  return jsonResp({
    list: [{
      vod_id: id,
      vod_name: title,
      vod_pic: proxyImage(rawPic, origin),
      vod_actor: "",
      vod_director: "",
      vod_remarks: `全${playUrls.length}集`,
      vod_content: rawDesc,
      vod_play_from: "野果专线",
      vod_play_url: playUrls.join("#")
    }]
  });
}

// ============================================================
// /play 播放地址 —— 关键修改：多参数名兼容 + episodeAll 精确匹配
// ============================================================

async function handlePlay(url) {
  const origin = url.origin;
  const id = url.searchParams.get("id") || "";
  if (!id) return jsonResp({ parse: 1, url: "" });

  // 解析 id = videoId:epNum[:realId][:epUrl]
  const parts = id.split(":");
  const vid      = parts[0] || "";
  const epStr    = parts[1] || "1";
  const epRealId = parts[2] || "";
  const epUrlEnc = parts[3] || "";

  const vNum  = /^\d+$/.test(vid)   ? parseInt(vid)   : vid;
  const epNum = /^\d+$/.test(epStr) ? parseInt(epStr) : epStr;
  const rid   = epRealId
    ? (/^\d+$/.test(epRealId) ? parseInt(epRealId) : epRealId)
    : null;

  // 首选：详情接口已经带回了直链，直接用，不再请求
  if (epUrlEnc) {
    try {
      const cachedUrl = decodeURIComponent(epUrlEnc);
      if (cachedUrl) {
        let finalUrl = cachedUrl;
        if (cachedUrl.includes(".m3u8")) {
          finalUrl = `${origin}/proxy?url=${encodeURIComponent(cachedUrl)}`;
        }
        if (url.searchParams.get("redirect") === "1") {
          return Response.redirect(finalUrl, 302);
        }
        return jsonResp({
          parse: 0,
          url: finalUrl,
          header: {
            "User-Agent": UA,
            "Referer": SITE + "/",
            "Origin": SITE
          }
        });
      }
    } catch (e) {}
  }

  // 否则请求后端：把所有可能的参数名一起发过去，最大化兼容
  const reqBody = {
    video_id: vNum,
    vid:      vNum,
    ep:       epNum,
    sort:     epNum,
    episode:  epNum,
    index:    epNum,
    page:     epNum
  };
  if (rid !== null) {
    reqBody.episode_id       = rid;
    reqBody.epid             = rid;
    reqBody.eid              = rid;
    reqBody.nid              = rid;
    reqBody.id               = rid;
    reqBody.video_episode_id = rid;
  }

  const d = await apiPost("/api/playlet/play", reqBody, true);
  let info = unwrap(d);

  if (info && typeof info === "object" && info.video_url === undefined &&
      info.data && typeof info.data === "object") {
    info = info.data;
  }
  if (!info || typeof info !== "object") info = {};

  let videoUrl = "";

  // 1) 从 episodeAll 精确匹配当前集（优先按 sort / index 匹配）
  if (Array.isArray(info.episodeAll)) {
    for (const e of info.episodeAll) {
      const s = String(
        e.sort !== undefined ? e.sort :
        (e.index !== undefined ? e.index :
        (e.episode !== undefined ? e.episode : ""))
      );
      if (s === String(epNum)) {
        videoUrl = String(e.video_url || e.url || e.play_url || "").trim();
        if (videoUrl) break;
      }
    }
    // 再按剧集真实 ID 匹配
    if (!videoUrl && rid !== null) {
      for (const e of info.episodeAll) {
        const eid = String(
          e.id !== undefined ? e.id :
          (e.episode_id !== undefined ? e.episode_id :
          (e.nid !== undefined ? e.nid : ""))
        );
        if (eid === String(rid)) {
          videoUrl = String(e.video_url || e.url || e.play_url || "").trim();
          if (videoUrl) break;
        }
      }
    }
    // 兜底：按数组下标取
    if (!videoUrl) {
      const idx = Number(epNum) - 1;
      if (idx >= 0 && idx < info.episodeAll.length) {
        const e = info.episodeAll[idx];
        videoUrl = String(e.video_url || e.url || e.play_url || "").trim();
      }
    }
  }

  // 2) 回退到顶层 video_url
  if (!videoUrl) {
    videoUrl = String(info.video_url || info.url || info.play_url || "").trim();
  }

  if (!videoUrl) {
    return jsonResp({ parse: 1, url: "" });
  }

  // m3u8 走代理（重写内部分片地址），mp4 直接返回
  let finalUrl = videoUrl;
  if (videoUrl.includes(".m3u8")) {
    finalUrl = `${origin}/proxy?url=${encodeURIComponent(videoUrl)}`;
  }

  // CarPlay / IPTV：M3U 里的播放地址带 redirect=1，直接 302 到流
  if (url.searchParams.get("redirect") === "1") {
    return Response.redirect(finalUrl, 302);
  }

  return jsonResp({
    parse: 0,
    url: finalUrl,
    header: {
      "User-Agent": UA,
      "Referer": SITE + "/",
      "Origin": SITE
    }
  });
}

// ============================================================
// /search 搜索
// ============================================================

async function handleSearch(url) {
  const origin = url.origin;
  const wd = url.searchParams.get("wd") || url.searchParams.get("key") || "";
  const pg = parseInt(url.searchParams.get("pg") || "1");
  if (!wd) return jsonResp({ list: [], page: 1, pagecount: 1, limit: 0, total: 0 });

  const d = await apiPost("/api/search/result", { keyword: wd, page: pg });
  const list = listFromPayload(d, origin);

  return jsonResp({
    list,
    page: pg,
    pagecount: list.length >= 20 ? pg + 1 : pg,
    limit: list.length,
    total: 9999
  });
}

// ============================================================
// /proxy 代理（图片 + m3u8 + ts 一并处理）
// ============================================================

async function handleProxy(url) {
  const target = url.searchParams.get("url");
  if (!target) return new Response("Missing url", { status: 400 });

  let res;
  try {
    res = await fetch(target, {
      headers: {
        "User-Agent": UA,
        "Referer": SITE + "/",
        "Origin": SITE,
        "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8"
      },
      redirect: "follow"
    });
  } catch (e) {
    return new Response("Fetch error: " + e.message, { status: 502 });
  }
  if (!res.ok) return new Response("Upstream " + res.status, { status: res.status });

  let contentType = res.headers.get("content-type") || "";
  const buf = new Uint8Array(await res.arrayBuffer());
  // 封面图按魔数纠正 MIME，避免不显示
  if (buf.length >= 3) {
    if (buf[0] === 0xFF && buf[1] === 0xD8) contentType = "image/jpeg";
    else if (buf[0] === 0x89 && buf[1] === 0x50) contentType = "image/png";
    else if (buf[0] === 0x47 && buf[1] === 0x49) contentType = "image/gif";
    else if (buf.length >= 12 && buf[0] === 0x52 && buf[8] === 0x57) contentType = "image/webp";
  }

  // 1) m3u8 重写
  const head = new TextDecoder().decode(buf.slice(0, 16));
  if (head.startsWith("#EXTM3U") || /mpegurl|m3u8/i.test(contentType)) {
    const text = new TextDecoder().decode(buf);
    const rewritten = rewriteM3u8(text, target, url.origin);
    return new Response(rewritten, {
      headers: {
        "Content-Type": "application/vnd.apple.mpegurl; charset=utf-8",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-cache"
      }
    });
  }

  // 2) 图片明文
  const mime = detectMime(buf);
  if (mime) {
    return new Response(buf, {
      headers: {
        "Content-Type": mime,
        "Cache-Control": "public, max-age=86400",
        "Access-Control-Allow-Origin": "*"
      }
    });
  }

  // 3) 尝试 AES 解密成图片
  const dec = await aesCbcDecrypt(buf, MEDIA_KEY, MEDIA_IV);
  if (dec) {
    const m2 = detectMime(dec);
    if (m2) {
      return new Response(dec, {
        headers: {
          "Content-Type": m2,
          "Cache-Control": "public, max-age=86400",
          "Access-Control-Allow-Origin": "*"
        }
      });
    }
  }

  // 4) 其他二进制（ts 分片等）
  return new Response(buf, {
    headers: {
      "Content-Type": contentType || "application/octet-stream",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "public, max-age=3600"
    }
  });
}

function rewriteM3u8(content, baseUrl, origin) {
  const lines = content.split(/\r?\n/);
  const result = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) { result.push(line); continue; }

    if (trimmed.startsWith("#")) {
      const replaced = line.replace(/URI="([^"]+)"/g, (m, u) => {
        try {
          const abs = new URL(u, baseUrl).toString();
          return `URI="${origin}/proxy?url=${encodeURIComponent(abs)}"`;
        } catch (e) { return m; }
      });
      result.push(replaced);
      continue;
    }

    try {
      const abs = new URL(trimmed, baseUrl).toString();
      result.push(`${origin}/proxy?url=${encodeURIComponent(abs)}`);
    } catch (e) {
      result.push(line);
    }
  }
  return result.join("\n");
}

// ============================================================
// /live.m3u  — CarPlay / IPTV 订阅（对齐 91：列表展平 + 封面 /proxy AES 解密）
// ============================================================

function attrValue(s) {
  return String(s == null ? "" : s).replace(/"/g, "'").replace(/[\r\n]+/g, " ").trim();
}

async function fetchCatPage(cat, pg, origin) {
  let d;
  if (cat.type_id === "rank") {
    d = await apiPost("/api/theater/videoRank", { page: pg, limit: 30 });
  } else if (BG_MAP[cat.type_id] !== undefined) {
    d = await apiPost("/api/theater/exploreList", { page: pg, limit: 30, background: BG_MAP[cat.type_id] });
  } else if (SETTING_MAP[cat.type_id] !== undefined) {
    d = await apiPost("/api/theater/exploreList", { page: pg, limit: 30, setting: SETTING_MAP[cat.type_id] });
  } else {
    d = await apiPost("/api/theater/exploreList", { page: pg, limit: 30 });
  }
  const list = listFromPayload(d, origin);
  return { list: list.map(v => ({ ...v, group: cat.type_name })), rawKeys: d && typeof d === "object" ? Object.keys(d) : [], n: list.length };
}

async function handleLiveM3u(url) {
  const origin = url.origin;
  const pages = Math.max(1, Math.min(parseInt(url.searchParams.get("pages") || String(M3U_PAGES_PER_CAT), 10) || M3U_PAGES_PER_CAT, 6));
  const defaultEps = Math.max(1, Math.min(parseInt(url.searchParams.get("eps") || String(M3U_DEFAULT_EPS), 10) || M3U_DEFAULT_EPS, M3U_MAX_EPS));
  // 默认少而稳：发现 + 排行（和网页同源接口）
  const want = (url.searchParams.get("cats") || "explore,rank")
    .split(",").map(s => s.trim()).filter(Boolean);
  const cats = CLASSES.filter(c => want.includes(c.type_id));
  const useCats = cats.length ? cats : CLASSES.slice(0, 2);

  const items = [];
  const seen = new Set();
  const diag = [];

  // 1) 先走首页（网页同源，最稳）
  try {
    const dHome = await apiPost("/api/home/homePage", {});
    const homeList = listFromPayload(dHome, origin);
    diag.push("home=" + homeList.length);
    for (const v of homeList) {
      if (!v || !v.vod_id || seen.has(v.vod_id)) continue;
      seen.add(v.vod_id);
      items.push({ ...v, group: "发现" });
    }
    // modules / top_list 额外捞
    const u = unwrap(dHome);
    if (u && typeof u === "object") {
      const extra = [];
      if (Array.isArray(u.top_list)) extra.push(...u.top_list);
      const mods = (u.modules && u.modules.list) || u.modules || [];
      if (Array.isArray(mods)) {
        for (const mod of mods) {
          if (mod && Array.isArray(mod.list)) extra.push(...mod.list);
          else if (mod && (mod.video_id || mod.id)) extra.push(mod);
        }
      }
      for (const it of extra) {
        const v = toVod(it, origin);
        if (v && !seen.has(v.vod_id)) {
          seen.add(v.vod_id);
          items.push({ ...v, group: "发现" });
        }
      }
      diag.push("homeExtra=" + extra.length);
    }
  } catch (e) {
    diag.push("homeErr=" + (e && e.message ? e.message : e));
  }

  // 2) 再顺序拉分类列表（避免并发被限流）
  for (const cat of useCats) {
    for (let pg = 1; pg <= pages; pg++) {
      try {
        const r = await fetchCatPage(cat, pg, origin);
        diag.push(cat.type_id + "p" + pg + "=" + r.n);
        for (const v of r.list) {
          if (!v || !v.vod_id || seen.has(v.vod_id)) continue;
          seen.add(v.vod_id);
          items.push(v);
        }
      } catch (e) {
        diag.push(cat.type_id + "p" + pg + "=ERR");
      }
    }
  }

  // 展平剧集
  const lines = ["#EXTM3U"];
  let chCount = 0;
  for (const it of items) {
    const epN = Math.min(Math.max(1, it._epHint || defaultEps), M3U_MAX_EPS);
    const logo = it.vod_pic || "";
    const group = it.group || "野果短剧";
    for (let ep = 1; ep <= epN; ep++) {
      const epLabel = "第" + String(ep).padStart(2, "0") + "集";
      const name = (it.vod_name + " " + epLabel).replace(/[\r\n]+/g, " ");
      const playId = it.vod_id + ":" + ep + "::";
      const parts = [
        "#EXTINF:-1",
        'tvg-id="' + attrValue(it.vod_id + "_" + ep) + '"',
        'tvg-name="' + attrValue(name) + '"'
      ];
      if (logo) parts.push('tvg-logo="' + attrValue(logo) + '"');
      parts.push('group-title="' + attrValue(group) + '"');
      lines.push(parts.join(" ") + "," + name);
      lines.push(origin + "/play?id=" + encodeURIComponent(playId) + "&redirect=1");
      chCount++;
    }
  }

  if (chCount === 0) {
    // 把诊断信息写进频道名，方便在播放器里直接看到
    const tip = "野果空列表 diag:" + diag.join("|");
    lines.push('#EXTINF:-1 tvg-name="' + attrValue(tip) + '" group-title="系统",' + tip);
    lines.push(origin + "/debug");
  }

  return new Response(lines.join("\n") + "\n", {
    headers: {
      "Content-Type": "application/vnd.apple.mpegurl; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store",
      "X-Channel-Count": String(chCount),
      "X-Series-Count": String(items.length),
      "X-Diag": diag.join(";")
    }
  });
}

// ============================================================
// 入口
// ============================================================

const INDEX_HTML = "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no\">\n<title>\u91ce\u679c\u77ed\u5267</title>\n<script src=\"https://cdn.jsdelivr.net/npm/hls.js@1.5.13/dist/hls.min.js\"></script>\n<style>\n  * { margin: 0; padding: 0; box-sizing: border-box; -webkit-tap-highlight-color: transparent; }\n  :root {\n    --bg: #0f1115; --panel: #181b22; --card: #1e222b; --line: #262b36;\n    --text: #e8eaed; --sub: #8b93a7; --accent: #ff7a4d; --accent2: #ffb35c;\n  }\n  html, body {\n    background: var(--bg); color: var(--text);\n    font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif;\n    min-height: 100vh; overflow-x: hidden;\n  }\n  a { color: inherit; text-decoration: none; }\n  img { display: block; width: 100%; height: 100%; object-fit: cover; }\n\n  header {\n    position: sticky; top: 0; z-index: 100;\n    background: rgba(15,17,21,.92);\n    backdrop-filter: saturate(180%) blur(16px);\n    border-bottom: 1px solid var(--line);\n    padding: 10px 14px;\n  }\n  .top { display: flex; align-items: center; gap: 10px; max-width: 1400px; margin: 0 auto; }\n  .logo {\n    font-size: 19px; font-weight: 800;\n    background: linear-gradient(90deg, var(--accent), var(--accent2));\n    -webkit-background-clip: text; background-clip: text; color: transparent;\n    letter-spacing: .5px; flex-shrink: 0; cursor: pointer;\n  }\n  .search {\n    flex: 1; display: flex; background: var(--card);\n    border: 1px solid var(--line); border-radius: 10px;\n    overflow: hidden; max-width: 560px; margin-left: auto;\n  }\n  .search input {\n    flex: 1; background: transparent; border: none; outline: none;\n    color: var(--text); padding: 9px 12px; font-size: 14px;\n  }\n  .search input::placeholder { color: var(--sub); }\n  .search button {\n    background: var(--accent); border: none; color: #fff;\n    padding: 0 16px; font-size: 14px; font-weight: 600; cursor: pointer;\n  }\n  .search button:active { opacity: .8; }\n\n  .cats {\n    display: flex; gap: 8px; overflow-x: auto;\n    padding: 10px 14px 2px; max-width: 1400px; margin: 0 auto;\n    scrollbar-width: none;\n  }\n  .cats::-webkit-scrollbar { display: none; }\n  .cat {\n    flex-shrink: 0; padding: 6px 14px; border-radius: 20px;\n    background: var(--card); border: 1px solid var(--line);\n    font-size: 13px; color: var(--sub); cursor: pointer;\n    transition: .2s; white-space: nowrap;\n  }\n  .cat.active {\n    background: linear-gradient(135deg, var(--accent), var(--accent2));\n    color: #fff; border-color: transparent; font-weight: 600;\n  }\n\n  main { max-width: 1400px; margin: 0 auto; padding: 14px; padding-bottom: 80px; }\n\n  .grid {\n    display: grid;\n    grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));\n    gap: 12px;\n  }\n  @media (max-width: 640px) { .grid { grid-template-columns: repeat(3, 1fr); gap: 8px; } }\n  @media (min-width: 900px) { .grid { grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 16px; } }\n\n  .card {\n    background: var(--card); border-radius: 10px; overflow: hidden;\n    cursor: pointer; transition: transform .18s, box-shadow .18s;\n    border: 1px solid var(--line);\n  }\n  .card:active { transform: scale(.97); }\n  @media (hover: hover) {\n    .card:hover { transform: translateY(-3px); box-shadow: 0 8px 24px rgba(0,0,0,.5); }\n    .card:hover .thumb img { transform: scale(1.06); }\n  }\n  .thumb { position: relative; aspect-ratio: 3 / 4; background: #0a0c10; overflow: hidden; }\n  .thumb img { transition: transform .35s; background: #0a0c10; }\n  .badge {\n    position: absolute; left: 6px; bottom: 6px;\n    background: rgba(0,0,0,.72); color: #fff; font-size: 11px;\n    padding: 2px 7px; border-radius: 4px; backdrop-filter: blur(4px);\n    max-width: calc(100% - 12px);\n    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;\n  }\n  .card-title {\n    padding: 8px 9px 10px; font-size: 13px; line-height: 1.35;\n    color: var(--text); display: -webkit-box;\n    -webkit-line-clamp: 2; -webkit-box-orient: vertical;\n    overflow: hidden; min-height: 44px;\n  }\n\n  .skel .thumb { background: linear-gradient(90deg,#1a1e26,#232833,#1a1e26); background-size: 200% 100%; animation: sk 1.2s infinite; }\n  .skel .card-title { background: #1a1e26; color: transparent; border-radius: 4px; margin: 8px 9px 10px; min-height: 30px; }\n  @keyframes sk { 0%{background-position:200% 0} 100%{background-position:-200% 0} }\n\n  .loadmore { text-align: center; padding: 22px 0 8px; color: var(--sub); font-size: 13px; cursor: pointer; }\n  .loadmore:active { color: var(--accent); }\n\n  .player-toolbar {\n    display: flex; align-items: center; justify-content: space-between;\n    margin-bottom: 10px;\n  }\n  .toolbar-right { display: flex; gap: 8px; align-items: center; }\n\n  .close-btn {\n    width: 36px; height: 36px; border-radius: 50%;\n    background: var(--card); color: var(--sub);\n    border: 1px solid var(--line);\n    font-size: 16px; line-height: 1;\n    display: flex; align-items: center; justify-content: center;\n    cursor: pointer; transition: .15s; padding: 0;\n    flex-shrink: 0;\n  }\n  .close-btn:hover {\n    background: rgba(255,122,77,.15);\n    color: var(--accent);\n    border-color: rgba(255,122,77,.5);\n  }\n  .close-btn:active { transform: scale(.92); }\n\n  .player-wrap {\n    position: relative; width: 100%; background: #000;\n    border-radius: 10px; overflow: hidden; margin-bottom: 14px;\n  }\n  video { width: 100%; display: block; background: #000; max-height: 78vh; }\n\n  .detail-head { display: flex; gap: 14px; margin-bottom: 14px; }\n  .detail-head .poster {\n    width: 120px; flex-shrink: 0; aspect-ratio: 3/4;\n    border-radius: 8px; overflow: hidden; background: #0a0c10;\n  }\n  @media (max-width: 560px) { .detail-head .poster { width: 100px; } }\n  .detail-info h1 { font-size: 17px; line-height: 1.4; margin-bottom: 8px; font-weight: 700; }\n  .detail-info .tags { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 8px; }\n  .tag {\n    font-size: 12px; padding: 3px 9px; border-radius: 12px;\n    background: var(--panel); color: var(--sub); border: 1px solid var(--line);\n  }\n  .desc {\n    font-size: 12.5px; line-height: 1.6; color: var(--sub);\n    display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical;\n    overflow: hidden;\n  }\n\n  .back-btn {\n    display: inline-flex; align-items: center; gap: 6px;\n    font-size: 14px; color: var(--sub); padding: 6px 0 12px; cursor: pointer;\n  }\n  .back-btn:active { color: var(--accent); }\n\n  .ep-section-title {\n    font-size: 14px; font-weight: 600; color: var(--text);\n    margin: 18px 0 10px;\n  }\n  .episodes {\n    display: grid;\n    grid-template-columns: repeat(auto-fill, minmax(72px, 1fr));\n    gap: 8px;\n  }\n  .ep {\n    background: var(--panel); border: 1px solid var(--line);\n    border-radius: 8px; padding: 8px 4px;\n    font-size: 12.5px; color: var(--sub); text-align: center;\n    cursor: pointer; transition: .15s;\n    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;\n    user-select: none;\n  }\n  .ep:hover { color: var(--text); border-color: #3a4050; }\n  .ep.on {\n    background: rgba(255,122,77,.15);\n    color: var(--accent); border-color: rgba(255,122,77,.5);\n    font-weight: 600;\n  }\n\n  .empty { text-align: center; padding: 60px 20px; color: var(--sub); font-size: 14px; }\n  .empty .ico { font-size: 40px; margin-bottom: 12px; opacity: .5; }\n\n  .player-error {\n    position: absolute; inset: 0; display: flex; flex-direction: column;\n    align-items: center; justify-content: center;\n    background: rgba(0,0,0,.85); color: #fff; gap: 12px;\n    font-size: 14px; padding: 20px; text-align: center;\n  }\n  .player-error button {\n    background: var(--accent); border: none; color: #fff;\n    padding: 9px 22px; border-radius: 8px; font-size: 14px;\n    cursor: pointer; font-weight: 600;\n  }\n\n  .topbar {\n    position: fixed; top: 0; left: 0; height: 2px;\n    background: linear-gradient(90deg, var(--accent), var(--accent2));\n    width: 0; z-index: 999; transition: width .25s;\n  }\n</style>\n</head>\n<body>\n\n<div class=\"topbar\" id=\"topbar\"></div>\n\n<header>\n  <div class=\"top\">\n    <div class=\"logo\" onclick=\"goHome()\">\u91ce\u679c\u77ed\u5267</div>\n    <div class=\"search\">\n      <input id=\"wd\" type=\"search\" placeholder=\"\u641c\u7d22\u77ed\u5267\u2026\" autocomplete=\"off\"\n             onkeydown=\"if(event.key==='Enter')doSearch()\">\n      <button onclick=\"doSearch()\">\u641c\u7d22</button>\n    </div>\n  </div>\n  <div class=\"cats\" id=\"cats\"></div>\n</header>\n\n<main id=\"app\"></main>\n\n<script>\n/* ============ \u914d\u7f6e ============ */\nconst API_BASE = \"\";\nconst ORIGIN_API = \"https://yeguodj.com/api.php\";\nconst ORIGIN_SITE = \"https://yeguodj.com\";\nconst AES_KEY_STR = \"2acf7e91e9864673\";\nconst AES_IV_STR  = \"1c29882d3ddfcfd6\";\n\nconst BG_MAP = {\n  dushi: 40, xiandai: 39, xiaoyuan: 47,\n  gudai: 41, xiangcun: 42, zhichang: 44,\n};\nconst SETTING_MAP = {\n  chongsheng: 26, chuanyue: 27, xitong: 28,\n  nixi: 53, mogai: 56,\n};\n\n/* ============ \u72b6\u6001 ============ */\nconst state = {\n  cats: [],\n  tid: \"explore\",\n  pg: 1,\n  list: [],\n  mode: \"home\",\n  keyword: \"\",\n  loading: false,\n  hasMore: true,\n  detail: null,\n  episodes: [],\n  currentEp: 0,\n  hls: null,\n  savedScrollY: 0,\n};\n\n/* ============ \u6e90\u7ad9\u76f4\u8fde + AES \u89e3\u5bc6\uff08\u4e0d\u7ecf\u8fc7 Worker\uff0c\u907f\u514d\u51fa\u53e3\u88ab\u6e90\u7ad9\u4e22\u5f03\uff09 ============ */\nfunction b64ToBytes(b64) {\n  const bin = atob(b64);\n  const out = new Uint8Array(bin.length);\n  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);\n  return out;\n}\nasync function aesDecrypt(b64) {\n  const key = await crypto.subtle.importKey(\n    \"raw\", new TextEncoder().encode(AES_KEY_STR), { name: \"AES-CBC\" }, false, [\"decrypt\"]\n  );\n  const iv = new TextEncoder().encode(AES_IV_STR);\n  const dec = await crypto.subtle.decrypt({ name: \"AES-CBC\", iv }, key, b64ToBytes(b64));\n  let text = new TextDecoder().decode(dec).trim();\n  const lb = Math.max(text.lastIndexOf(\"}\"), text.lastIndexOf(\"]\"));\n  if (lb > 0) text = text.slice(0, lb + 1);\n  return JSON.parse(text);\n}\nasync function originPost(path, body) {\n  const r = await fetch(ORIGIN_API + path, {\n    method: \"POST\",\n    headers: {\n      \"Content-Type\": \"application/json;charset=UTF-8\",\n      \"Accept\": \"application/json, text/plain, */*\"\n    },\n    body: JSON.stringify(body || {})\n  });\n  if (!r.ok) throw new Error(\"HTTP \" + r.status);\n  let d = await r.json();\n  for (let i = 0; i < 2; i++) {\n    if (d && typeof d.data === \"string\" && d.data.length > 20) {\n      d = await aesDecrypt(d.data);\n    } else if (d && d.data && typeof d.data === \"object\") {\n      d = d.data;\n    } else break;\n  }\n  if (d && d.data && typeof d.data === \"object\" && (d.data.list || d.data.episodes || d.data.video_url || d.data.top_list)) {\n    return d.data;\n  }\n  return d || {};\n}\nfunction proxyPic(pic) {\n  pic = String(pic || \"\").trim();\n  if (!pic) return \"\";\n  if (pic.includes(\"/proxy?url=\")) return pic;\n  // \u8d70\u672c\u7ad9\u4ee3\u7406\uff0c\u5e26\u4e0a\u6e90\u7ad9 Referer\uff0c\u89e3\u51b3\u56fe\u5e8a\u9632\u76d7\u94fe\u5bfc\u81f4\u65e0\u5c01\u9762\n  return \"/proxy?url=\" + encodeURIComponent(pic);\n}\nfunction toVod(it) {\n  if (!it) return null;\n  const id = String(it.video_id != null ? it.video_id : (it.id || \"\")).trim();\n  if (!id) return null;\n  const pic = String(it.cover || it.cover_img || it.pic || \"\").trim();\n  return {\n    vod_id: id,\n    vod_name: String(it.title || it.video_title || it.name || id).trim(),\n    vod_pic: proxyPic(pic),\n    vod_remarks: String(it.serialize_status_text || it.update_status || \"\").trim()\n  };\n}\nfunction listFrom(data) {\n  const arr = (data && data.list) || (data && data.top_list) || (Array.isArray(data) ? data : []);\n  const out = [], seen = new Set();\n  for (const it of arr) {\n    const v = toVod(it);\n    if (v && !seen.has(v.vod_id)) { seen.add(v.vod_id); out.push(v); }\n  }\n  return out;\n}\n\n/* \u517c\u5bb9\u539f\u524d\u7aef\u7684 api(path) \u8c03\u7528 */\nasync function api(path, params) {\n  params = params || {};\n  // \u9996\u9875\n  if (path === \"/home\") {\n    let list = [];\n    try {\n      const home = await originPost(\"/api/home/homePage\", {});\n      const combined = [];\n      if (home.top_list) combined.push(...home.top_list);\n      const mods = (home.modules && home.modules.list) || [];\n      for (const m of mods) {\n        if (m && Array.isArray(m.list)) combined.push(...m.list);\n        else if (m && (m.video_id || m.id)) combined.push(m);\n      }\n      if (Array.isArray(home.list)) combined.push(...home.list);\n      list = listFrom({ list: combined });\n    } catch (e) { console.warn(\"homePage\", e); }\n    if (!list.length) {\n      const exp = await originPost(\"/api/theater/exploreList\", { page: 1, limit: 30 });\n      list = listFrom(exp);\n    }\n    return {\n      class: [\n        { type_id: \"explore\", type_name: \"\u53d1\u73b0\" },\n        { type_id: \"rank\", type_name: \"\u6392\u884c\u699c\" },\n        { type_id: \"dushi\", type_name: \"\u90fd\u5e02\" },\n        { type_id: \"xiandai\", type_name: \"\u73b0\u4ee3\" },\n        { type_id: \"xiaoyuan\", type_name: \"\u6821\u56ed\" },\n        { type_id: \"gudai\", type_name: \"\u53e4\u4ee3\" },\n        { type_id: \"xiangcun\", type_name: \"\u4e61\u6751\" },\n        { type_id: \"zhichang\", type_name: \"\u804c\u573a\" },\n        { type_id: \"chongsheng\", type_name: \"\u91cd\u751f\" },\n        { type_id: \"chuanyue\", type_name: \"\u7a7f\u8d8a\" },\n        { type_id: \"xitong\", type_name: \"\u7cfb\u7edf\" },\n        { type_id: \"nixi\", type_name: \"\u9006\u88ad\" },\n        { type_id: \"mogai\", type_name: \"\u9b54\u6539\" }\n      ],\n      list\n    };\n  }\n  // \u5206\u7c7b\n  if (path === \"/category\") {\n    const tid = params.tid || \"explore\";\n    const pg = parseInt(params.pg || \"1\", 10) || 1;\n    let data;\n    if (tid === \"rank\") {\n      data = await originPost(\"/api/theater/videoRank\", { page: pg, limit: 24 });\n    } else if (BG_MAP[tid] != null) {\n      data = await originPost(\"/api/theater/exploreList\", { page: pg, limit: 24, background: BG_MAP[tid] });\n    } else if (SETTING_MAP[tid] != null) {\n      data = await originPost(\"/api/theater/exploreList\", { page: pg, limit: 24, setting: SETTING_MAP[tid] });\n    } else {\n      data = await originPost(\"/api/theater/exploreList\", { page: pg, limit: 24 });\n    }\n    const list = listFrom(data);\n    return { list, page: pg, pagecount: list.length >= 24 ? pg + 1 : pg, limit: 24, total: 9999 };\n  }\n  // \u641c\u7d22\n  if (path === \"/search\") {\n    const wd = params.wd || \"\";\n    const pg = parseInt(params.pg || \"1\", 10) || 1;\n    let data = {};\n    try {\n      data = await originPost(\"/api/theater/search\", { keyword: wd, page: pg, limit: 24 });\n    } catch (e) {\n      try { data = await originPost(\"/api/playlet/search\", { keyword: wd, page: pg, limit: 24 }); } catch (e2) {}\n    }\n    return { list: listFrom(data) };\n  }\n  // \u8be6\u60c5\n  if (path === \"/detail\") {\n    const id = params.id || params.ids || \"\";\n    const det = await originPost(\"/api/playlet/detail\", { video_id: /^\\d+$/.test(id) ? parseInt(id, 10) : id });\n    const eps = Array.isArray(det.episodes) ? det.episodes : [];\n    const playUrls = eps.map((e, i) => {\n      const sort = e.sort != null ? e.sort : (i + 1);\n      const name = e.title || (\"\u7b2c\" + sort + \"\u96c6\");\n      const playId = [id, sort, e.id != null ? e.id : \"\"].join(\":\");\n      return name + \"$\" + playId;\n    });\n    if (!playUrls.length) playUrls.push(\"\u7b2c1\u96c6$\" + id + \":1:\");\n    return {\n      list: [{\n        vod_id: String(det.video_id || id),\n        vod_name: det.title || id,\n        vod_pic: proxyPic(det.cover || det.cover_img || \"\"),\n        vod_content: det.description || \"\",\n        vod_play_from: \"\u91ce\u679c\",\n        vod_play_url: playUrls.join(\"#\")\n      }]\n    };\n  }\n  // \u64ad\u653e\n  if (path === \"/play\") {\n    const raw = params.id || \"\";\n    const parts = String(raw).split(\":\");\n    const videoId = parts[0];\n    const ep = parts[1] || \"1\";\n    const eid = parts[2] || \"\";\n    const body = { video_id: /^\\d+$/.test(videoId) ? parseInt(videoId, 10) : videoId, sort: parseInt(ep, 10) || 1, ep: parseInt(ep, 10) || 1 };\n    if (eid) body.episode_id = /^\\d+$/.test(eid) ? parseInt(eid, 10) : eid;\n    let info = await originPost(\"/api/playlet/play\", body);\n    let url = String(info.video_url || info.url || info.play_url || \"\").trim();\n    if (!url && !eid) {\n      const det = await originPost(\"/api/playlet/detail\", { video_id: body.video_id });\n      const list = det.episodes || [];\n      const target = list.find(e => String(e.sort) === String(ep)) || list[0];\n      if (target && target.id != null) {\n        info = await originPost(\"/api/playlet/play\", { video_id: body.video_id, episode_id: target.id, sort: target.sort || ep });\n        url = String(info.video_url || info.url || info.play_url || \"\").trim();\n      }\n    }\n    return { parse: 0, url: url || \"\", header: { \"User-Agent\": navigator.userAgent, \"Referer\": ORIGIN_SITE + \"/\" } };\n  }\n  // \u5176\u5b83\u4ecd\u8d70\u672c\u7ad9 Worker\n  const qs = params ? \"?\" + new URLSearchParams(params).toString() : \"\";\n  return fetch(API_BASE + path + qs).then(r => r.json());\n}\n\nfunction progress(on) {\n  const bar = document.getElementById(\"topbar\");\n  if (on) { bar.style.width = \"70%\"; bar.style.opacity = \"1\"; }\n  else {\n    bar.style.width = \"100%\";\n    setTimeout(() => { bar.style.opacity = \"0\"; bar.style.width = \"0\"; }, 300);\n  }\n}\n\nfunction esc(s) {\n  return String(s || \"\").replace(/[&<>\"']/g, c =>\n    ({ \"&\":\"&amp;\",\"<\":\"&lt;\",\">\":\"&gt;\",'\"':\"&quot;\",\"'\":\"&#39;\" }[c]));\n}\n\n/* ============ \u5206\u7c7b\u680f ============ */\nfunction renderCats() {\n  const el = document.getElementById(\"cats\");\n  el.innerHTML = state.cats.map(c => `\n    <div class=\"cat ${state.mode === 'category' && state.tid === c.type_id ? 'active' : ''}\"\n         data-tid=\"${esc(c.type_id)}\">${esc(c.type_name)}</div>\n  `).join(\"\");\n  el.querySelectorAll(\".cat\").forEach(node => {\n    node.onclick = () => {\n      const tid = node.dataset.tid;\n      state.tid = tid; state.pg = 1; state.list = [];\n      state.mode = \"category\"; state.hasMore = true;\n      state.savedScrollY = 0;\n      renderCats();\n      renderList(true);\n      loadCategory();\n    };\n  });\n}\n\n/* ============ \u9996\u9875 ============ */\nasync function goHome() {\n  state.mode = \"home\"; state.pg = 1; state.list = []; state.hasMore = true;\n  state.keyword = \"\"; state.savedScrollY = 0;\n  document.getElementById(\"wd\").value = \"\";\n  renderCats();\n  progress(true);\n  try {\n    const data = await api(\"/home\");\n    if (data.class) state.cats = data.class;\n    state.list = data.list || [];\n    renderCats();\n    renderList();\n  } catch (e) {\n    renderEmpty(\"\u52a0\u8f7d\u5931\u8d25\uff0c\u8bf7\u7a0d\u540e\u91cd\u8bd5\");\n  }\n  progress(false);\n}\n\n/* ============ \u5206\u7c7b\u52a0\u8f7d ============ */\nasync function loadCategory() {\n  if (state.loading || !state.hasMore) return;\n  state.loading = true;\n  progress(true);\n  try {\n    const data = await api(\"/category\", { tid: state.tid, pg: state.pg });\n    const list = data.list || [];\n    if (list.length === 0) state.hasMore = false;\n    else {\n      state.list = state.list.concat(list);\n      state.pg++;\n    }\n    renderList();\n  } catch (e) {\n    state.hasMore = false;\n    if (state.list.length === 0) renderEmpty(\"\u52a0\u8f7d\u5931\u8d25\");\n  }\n  state.loading = false;\n  progress(false);\n}\n\n/* ============ \u641c\u7d22 ============ */\nasync function doSearch() {\n  const wd = document.getElementById(\"wd\").value.trim();\n  if (!wd) return;\n  state.mode = \"search\";\n  state.keyword = wd;\n  state.pg = 1; state.list = []; state.hasMore = true;\n  state.savedScrollY = 0;\n  document.querySelectorAll(\".cat\").forEach(n => n.classList.remove(\"active\"));\n  renderList(true);\n  progress(true);\n  try {\n    const data = await api(\"/search\", { wd, pg: 1 });\n    const list = data.list || [];\n    state.list = list;\n    state.pg = 2;\n    if (list.length === 0) state.hasMore = false;\n    renderList();\n    if (list.length === 0) renderEmpty(\"\u672a\u627e\u5230\u300c\" + esc(wd) + \"\u300d\u76f8\u5173\u77ed\u5267\");\n  } catch (e) {\n    renderEmpty(\"\u641c\u7d22\u5931\u8d25\");\n  }\n  progress(false);\n}\n\nasync function loadMoreSearch() {\n  if (state.loading || !state.hasMore) return;\n  state.loading = true;\n  try {\n    const data = await api(\"/search\", { wd: state.keyword, pg: state.pg });\n    const list = data.list || [];\n    if (list.length === 0) state.hasMore = false;\n    else { state.list = state.list.concat(list); state.pg++; }\n    renderList();\n  } catch (e) { state.hasMore = false; }\n  state.loading = false;\n}\n\n/* ============ \u5217\u8868\u6e32\u67d3 ============ */\nfunction renderList(skeleton) {\n  const app = document.getElementById(\"app\");\n\n  if (skeleton && state.list.length === 0) {\n    app.innerHTML = `<div class=\"grid\">${\n      Array.from({length: 12}).map(() => `\n        <div class=\"card skel\">\n          <div class=\"thumb\"></div>\n          <div class=\"card-title\"></div>\n        </div>`).join(\"\")\n    }</div>`;\n    return;\n  }\n\n  if (state.list.length === 0) return;\n\n  const cards = state.list.map((it, i) => `\n    <div class=\"card\" data-i=\"${i}\">\n      <div class=\"thumb\">\n        <img loading=\"lazy\" src=\"${esc(it.vod_pic)}\" alt=\"\"\n             onerror=\"this.style.opacity=.15\">\n        ${it.vod_remarks ? `<div class=\"badge\">${esc(it.vod_remarks)}</div>` : \"\"}\n      </div>\n      <div class=\"card-title\">${esc(it.vod_name)}</div>\n    </div>\n  `).join(\"\");\n\n  const more = state.mode === \"home\"\n    ? \"\"\n    : (state.hasMore\n        ? `<div class=\"loadmore\" id=\"loadmore\">\u52a0\u8f7d\u66f4\u591a \u2193</div>`\n        : `<div class=\"loadmore\" style=\"color:#555\">\u2014 \u5df2\u7ecf\u5230\u5e95\u4e86 \u2014</div>`);\n\n  app.innerHTML = `<div class=\"grid\">${cards}</div>${more}`;\n\n  app.querySelectorAll(\".card\").forEach(node => {\n    node.onclick = () => openDetail(state.list[+node.dataset.i]);\n  });\n\n  const lm = document.getElementById(\"loadmore\");\n  if (lm) {\n    lm.onclick = () => {\n      if (state.mode === \"category\") loadCategory();\n      else if (state.mode === \"search\") loadMoreSearch();\n    };\n  }\n}\n\nfunction renderEmpty(msg) {\n  document.getElementById(\"app\").innerHTML = `\n    <div class=\"empty\">\n      <div class=\"ico\">\ud83c\udfac</div>\n      <div>${msg || \"\u6682\u65e0\u5185\u5bb9\"}</div>\n    </div>`;\n}\n\n/* ============ \u8be6\u60c5\u9875 ============ */\nasync function openDetail(item) {\n  if (!item || !item.vod_id) return;\n\n  state.savedScrollY = window.scrollY || window.pageYOffset || 0;\n  state.mode = \"detail\";\n  state.detail = { ...item };\n  state.episodes = [];\n  state.currentEp = 0;\n  window.scrollTo(0, 0);\n\n  renderDetailSkeleton();\n\n  progress(true);\n  try {\n    const data = await api(\"/detail\", { id: item.vod_id });\n    const d = (data.list && data.list[0]) || null;\n    if (d) {\n      state.detail = d;\n      state.episodes = parseEpisodes(d.vod_play_url);\n      renderDetail();\n    }\n  } catch (e) {\n    console.log(\"detail error\", e);\n  }\n  progress(false);\n}\n\nfunction parseEpisodes(playUrl) {\n  if (!playUrl) return [];\n  return playUrl.split(\"#\").map(part => {\n    const idx = part.indexOf(\"$\");\n    if (idx < 0) return null;\n    return {\n      title: part.slice(0, idx).trim(),\n      playId: part.slice(idx + 1).trim(),\n    };\n  }).filter(Boolean);\n}\n\nfunction renderDetailSkeleton() {\n  document.getElementById(\"app\").innerHTML = `\n    <div class=\"player-toolbar\">\n      <div class=\"back-btn\" id=\"backBtn\" style=\"padding:0\">\u2190 \u8fd4\u56de\u5217\u8868</div>\n      <div class=\"toolbar-right\">\n        <button class=\"close-btn\" id=\"closeBtn\" title=\"\u5173\u95ed\">\u2715</button>\n      </div>\n    </div>\n    <div class=\"player-wrap\" id=\"playerWrap\">\n      <video id=\"video\" controls playsinline preload=\"metadata\"></video>\n    </div>\n    <div class=\"detail-head\">\n      <div class=\"poster\"></div>\n      <div class=\"detail-info\"><h1 style=\"color:var(--sub);font-size:15px\">\u52a0\u8f7d\u4e2d\u2026</h1></div>\n    </div>\n  `;\n  document.getElementById(\"backBtn\").onclick = closePlayer;\n  document.getElementById(\"closeBtn\").onclick = closePlayer;\n}\n\nfunction renderDetail() {\n  const app = document.getElementById(\"app\");\n  const d = state.detail || {};\n  const title = d.vod_name || \"\u77ed\u5267\";\n  const pic = d.vod_pic || \"\";\n  const desc = d.vod_content || \"\";\n  const remark = d.vod_remarks || \"\";\n\n  const epHtml = state.episodes.map((ep, i) => `\n    <div class=\"ep ${i === state.currentEp ? 'on' : ''}\" data-idx=\"${i}\">\n      ${esc(ep.title)}\n    </div>\n  `).join(\"\");\n\n  app.innerHTML = `\n    <div class=\"player-toolbar\">\n      <div class=\"back-btn\" id=\"backBtn\" style=\"padding:0\">\u2190 \u8fd4\u56de\u5217\u8868</div>\n      <div class=\"toolbar-right\">\n        <button class=\"close-btn\" id=\"closeBtn\" title=\"\u5173\u95ed\">\u2715</button>\n      </div>\n    </div>\n    <div class=\"player-wrap\" id=\"playerWrap\">\n      <video id=\"video\" controls playsinline preload=\"metadata\"\n             poster=\"${esc(pic)}\"></video>\n    </div>\n    <div class=\"detail-head\">\n      <div class=\"poster\"><img src=\"${esc(pic)}\" onerror=\"this.style.opacity=.15\"></div>\n      <div class=\"detail-info\">\n        <h1>${esc(title)}</h1>\n        <div class=\"tags\">\n          <span class=\"tag\">\u91ce\u679c\u77ed\u5267</span>\n          ${remark ? `<span class=\"tag\">${esc(remark)}</span>` : \"\"}\n        </div>\n        ${desc ? `<div class=\"desc\">${esc(desc)}</div>` : \"\"}\n      </div>\n    </div>\n    <div class=\"ep-section-title\">\u9009\u96c6\uff08\u5171 ${state.episodes.length} \u96c6\uff09</div>\n    <div class=\"episodes\">${epHtml || '<div style=\"color:var(--sub);font-size:13px\">\u6682\u65e0\u5267\u96c6</div>'}</div>\n  `;\n\n  document.getElementById(\"backBtn\").onclick = closePlayer;\n  document.getElementById(\"closeBtn\").onclick = closePlayer;\n\n  app.querySelectorAll(\".ep\").forEach(node => {\n    node.onclick = () => {\n      const idx = parseInt(node.dataset.idx);\n      if (idx !== state.currentEp) {\n        playEpisode(idx);\n      }\n    };\n  });\n\n  if (state.episodes.length > 0) {\n    playEpisode(0);\n  }\n}\n\n/* ============ \u64ad\u653e\u67d0\u4e00\u96c6 ============ */\nasync function playEpisode(idx) {\n  if (idx < 0 || idx >= state.episodes.length) return;\n  state.currentEp = idx;\n\n  document.querySelectorAll(\".ep\").forEach((el, i) => {\n    el.classList.toggle(\"on\", i === idx);\n  });\n\n  showPlayerLoading(`\u6b63\u5728\u52a0\u8f7d\u7b2c ${idx + 1} \u96c6\u2026`);\n\n  const ep = state.episodes[idx];\n  try {\n    const data = await api(\"/play\", { id: ep.playId });\n    if (!data || !data.url) {\n      showPlayerError(\"\u89e3\u6790\u64ad\u653e\u5730\u5740\u5931\u8d25\");\n      return;\n    }\n    playVideo(data.url);\n  } catch (e) {\n    showPlayerError(\"\u8bf7\u6c42\u5931\u8d25\uff1a\" + (e.message || e));\n  }\n}\n\nfunction closePlayer() {\n  destroyPlayer();\n  const backMode = (state.mode === \"search\") ? \"search\" : \"category\";\n  state.mode = backMode;\n  state.detail = null;\n  state.episodes = [];\n  renderList();\n  if (backMode === \"category\") renderCats();\n  requestAnimationFrame(() => {\n    window.scrollTo(0, state.savedScrollY || 0);\n  });\n}\n\n/* ============ \u64ad\u653e\u5668 ============ */\nfunction destroyPlayer() {\n  if (state.hls) {\n    try { state.hls.destroy(); } catch (e) {}\n    state.hls = null;\n  }\n  const v = document.getElementById(\"video\");\n  if (v) {\n    try { v.pause(); } catch (e) {}\n    try { v.removeAttribute(\"src\"); v.load(); } catch (e) {}\n    v.onended = null;\n  }\n}\n\nfunction showPlayerLoading(msg) {\n  const wrap = document.getElementById(\"playerWrap\");\n  if (!wrap) return;\n  wrap.querySelectorAll(\".player-error\").forEach(n => n.remove());\n  const div = document.createElement(\"div\");\n  div.className = \"player-error\";\n  div.style.background = \"rgba(0,0,0,.6)\";\n  div.innerHTML = `<div>${esc(msg)}</div>`;\n  wrap.appendChild(div);\n}\n\nfunction showPlayerError(msg) {\n  const wrap = document.getElementById(\"playerWrap\");\n  if (!wrap) return;\n  wrap.querySelectorAll(\".player-error\").forEach(n => n.remove());\n  const div = document.createElement(\"div\");\n  div.className = \"player-error\";\n  div.innerHTML = `\n    <div>\u26a0\ufe0f ${esc(msg)}</div>\n    <button id=\"retryPlay\">\u91cd\u8bd5</button>`;\n  wrap.appendChild(div);\n  div.querySelector(\"#retryPlay\").onclick = () => {\n    div.remove();\n    playEpisode(state.currentEp);\n  };\n}\n\nfunction showPlayerLoadingHide() {\n  const wrap = document.getElementById(\"playerWrap\");\n  if (!wrap) return;\n  wrap.querySelectorAll(\".player-error\").forEach(n => n.remove());\n}\n\nfunction showFinishedOverlay() {\n  const wrap = document.getElementById(\"playerWrap\");\n  if (!wrap) return;\n  wrap.querySelectorAll(\".player-error\").forEach(n => n.remove());\n  const div = document.createElement(\"div\");\n  div.className = \"player-error\";\n  div.style.background = \"rgba(0,0,0,.75)\";\n  div.innerHTML = `<div>\ud83c\udf89 \u5df2\u770b\u5b8c\u6700\u540e\u4e00\u96c6</div>`;\n  wrap.appendChild(div);\n}\n\nfunction playVideo(src) {\n  destroyPlayer();\n\n  const v = document.getElementById(\"video\");\n  if (!v) return;\n\n  // \u591a\u96c6\u5168\u81ea\u52a8\u8fde\u64ad\n  v.onended = () => {\n    console.log(\"[play] ended \u2192 \u81ea\u52a8\u4e0b\u4e00\u96c6\");\n    const next = state.currentEp + 1;\n    if (next < state.episodes.length) {\n      playEpisode(next);\n      setTimeout(() => {\n        const el = document.querySelector(`.ep[data-idx=\"${next}\"]`);\n        if (el) el.scrollIntoView({ behavior: \"smooth\", block: \"nearest\" });\n      }, 100);\n    } else {\n      showFinishedOverlay();\n    }\n  };\n\n  const isM3u8 = src.includes(\".m3u8\") || src.includes(\"mpegurl\") || src.includes(\"/proxy?url=\");\n\n  if (isM3u8 && window.Hls && Hls.isSupported()) {\n    const hls = new Hls({\n      maxBufferLength: 30,\n      maxMaxBufferLength: 60,\n      enableWorker: true,\n      lowLatencyMode: false\n    });\n    state.hls = hls;\n    hls.loadSource(src);\n    hls.attachMedia(v);\n    hls.on(Hls.Events.MANIFEST_PARSED, () => {\n      showPlayerLoadingHide();\n      v.play().catch(() => {});\n    });\n    hls.on(Hls.Events.ERROR, (e, data) => {\n      if (data && data.fatal) {\n        switch (data.type) {\n          case Hls.ErrorTypes.NETWORK_ERROR:\n            showPlayerError(\"\u7f51\u7edc\u9519\u8bef\uff0c\u64ad\u653e\u5931\u8d25\");\n            break;\n          case Hls.ErrorTypes.MEDIA_ERROR:\n            try { hls.recoverMediaError(); }\n            catch (err) { showPlayerError(\"\u5a92\u4f53\u89e3\u7801\u5931\u8d25\"); }\n            break;\n          default:\n            showPlayerError(\"\u64ad\u653e\u5931\u8d25\uff1a\" + (data.details || \"\u672a\u77e5\u9519\u8bef\"));\n        }\n      }\n    });\n  } else {\n    v.src = src;\n    v.addEventListener(\"loadedmetadata\", () => {\n      showPlayerLoadingHide();\n      v.play().catch(() => {});\n    }, { once: true });\n    v.addEventListener(\"error\", () => showPlayerError(\"\u64ad\u653e\u5931\u8d25\"), { once: true });\n  }\n}\n\n/* ============ \u6eda\u52a8\u52a0\u8f7d ============ */\nlet scrollTimer = null;\nwindow.addEventListener(\"scroll\", () => {\n  if (state.mode === \"detail\") return;\n  if (scrollTimer) return;\n  scrollTimer = setTimeout(() => {\n    scrollTimer = null;\n    const nearBottom = window.innerHeight + window.scrollY >= document.body.offsetHeight - 400;\n    if (nearBottom) {\n      if (state.mode === \"category\") loadCategory();\n      else if (state.mode === \"search\") loadMoreSearch();\n    }\n  }, 200);\n});\n\n/* ============ \u542f\u52a8 ============ */\n(async function boot() {\n  try {\n    const data = await api(\"/home\");\n    if (data.class && data.class.length) {\n      state.cats = data.class;\n    }\n  } catch (e) {\n    console.warn(\"[boot] /home \u62c9\u53d6\u5931\u8d25\", e);\n  }\n\n  if (!state.cats.length) {\n    state.cats = [\n      { type_id: \"explore\", type_name: \"\u53d1\u73b0\" },\n      { type_id: \"rank\",    type_name: \"\u6392\u884c\u699c\" },\n      { type_id: \"dushi\",   type_name: \"\u90fd\u5e02\" },\n      { type_id: \"xiandai\", type_name: \"\u73b0\u4ee3\" },\n      { type_id: \"xiaoyuan\",type_name: \"\u6821\u56ed\" },\n      { type_id: \"gudai\",   type_name: \"\u53e4\u4ee3\" },\n      { type_id: \"xiangcun\",type_name: \"\u4e61\u6751\" },\n      { type_id: \"zhichang\",type_name: \"\u804c\u573a\" },\n      { type_id: \"chongsheng\", type_name: \"\u91cd\u751f\" },\n      { type_id: \"chuanyue\",   type_name: \"\u7a7f\u8d8a\" },\n      { type_id: \"xitong\",     type_name: \"\u7cfb\u7edf\" },\n      { type_id: \"nixi\",       type_name: \"\u9006\u88ad\" },\n      { type_id: \"mogai\",      type_name: \"\u9b54\u6539\" },\n    ];\n  }\n\n  state.mode = \"category\";\n  state.tid = \"explore\";\n  state.pg = 1;\n  state.list = [];\n  state.hasMore = true;\n  state.savedScrollY = 0;\n\n  renderCats();\n  renderList(true);\n  loadCategory();\n})();\n</script>\n</body>\n</html>";

const worker = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (env && env.SITE_HOST) setSite(String(env.SITE_HOST));

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "*"
        }
      });
    }

    try {
      if (path === "/live.m3u" || path === "/m3u") {
        return await handleLiveM3u(url);
      }

      if (API_PATHS.has(path)) {
        switch (path) {
          case "/home":     return await handleHome(url);
          case "/category": return await handleCategory(url);
          case "/detail":   return await handleDetail(url);
          case "/play":     return await handlePlay(url);
          case "/search":   return await handleSearch(url);
          case "/proxy":    return await handleProxy(url);
          case "/live.m3u":
          case "/m3u":      return await handleLiveM3u(url);
          case "/debug": {
            const d1 = await apiPost("/api/theater/exploreList", { page: 1, limit: 3 }, true);
            const u1 = unwrap(d1);
            const d2 = await apiPost("/api/home/homePage", {}, true);
            const u2 = unwrap(d2);
            const sample = listFromPayload(d1, url.origin);
            const sampleHome = listFromPayload(d2, url.origin);
            // 额外：裸请求源站首页，看 Worker 出网是否正常
            let siteProbe = {};
            try {
              const pr = await fetch(SITE + "/", { headers: { "User-Agent": UA }, redirect: "follow" });
              siteProbe = { status: pr.status, final: pr.url, len: (await pr.text()).length };
            } catch (e) {
              siteProbe = { err: String(e && e.message ? e.message : e) };
            }
            return new Response(JSON.stringify({
              site: SITE,
              api_base: API_BASE,
              candidates: SITE_CANDIDATES,
              site_probe: siteProbe,
              explore_meta: d1 && d1.__meta,
              explore_tried: d1 && d1.__tried,
              explore_raw_top: d1 && typeof d1 === "object" ? Object.keys(d1).filter(k => k !== "__meta" && k !== "__tried") : typeof d1,
              explore_keys: u1 && typeof u1 === "object" ? Object.keys(u1) : typeof u1,
              explore_list_len: (u1 && u1.list && u1.list.length) || 0,
              explore_parsed: sample.length,
              home_meta: d2 && d2.__meta,
              home_tried: d2 && d2.__tried,
              home_keys: u2 && typeof u2 === "object" ? Object.keys(u2) : typeof u2,
              home_parsed: sampleHome.length,
              sample_titles: sample.slice(0, 3).map(x => x.vod_name),
              sample_pic: sample[0] && sample[0].vod_pic,
              m3u_hint: url.origin + "/live.m3u",
              sample: sample.slice(0, 2)
            }, null, 2), { headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
          }
        }
      }

      if (env && env.ASSETS) {
        try {
          const asset = await env.ASSETS.fetch(request);
          if (asset && asset.status !== 404) return asset;
        } catch (e) {}
      }
      // Workers 单文件部署时没有 ASSETS，直接返回内置网页
      if (path === "/" || path === "/index.html" || path === "/index.htm") {
        return new Response(INDEX_HTML, {
          headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }
        });
      }
      return new Response(INDEX_HTML, {
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }
      });
    } catch (e) {
      console.log("[Worker Error]", e.message);
      return new Response("Worker Error: " + e.message, { status: 500 });
    }
  }
};

export default worker;

// Deno Deploy 入口（Cloudflare 不会执行）
if (typeof Deno !== "undefined" && typeof Deno.serve === "function") {
  Deno.serve((req) => worker.fetch(req, {}, {}));
}