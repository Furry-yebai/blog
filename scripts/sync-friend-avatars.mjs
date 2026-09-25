#!/usr/bin/env node

/**
 * 友链头像同步脚本
 *
 * 读取 src/data/friends/*.json，把每个友链的 avatar 远程图片拉取到
 * src/assets/friends/，并写入 src/data/friend-avatars.json 清单。
 * 页面只引用本站资源，不再依赖任何外链。
 *
 * 两个拉取时机：
 * - 发布：友链 JSON 提交后（Action 或本地手动）拉取一次，结果提交进仓库
 * - 构建：pnpm build 前再拉取一次；失败则回退到仓库中已发布的头像，
 *   仍没有则页面显示占位图。构建模式下任何错误都不会中断构建
 *
 * - 通过文件头魔数校验内容，防止把 WAF / 人机验证 HTML 页当成图片
 * - 通过文件头魔数校验内容，防止把 WAF / 人机验证 HTML 页当成图片
 * - 能被 sharp 解码的图片统一转为 160px webp；ICO 等无法解码的格式原样保存
 *
 * 用法：
 *   pnpm sync:friends            同步全部（发布时使用）
 *   node scripts/sync-friend-avatars.mjs --build  构建前使用，超时更短且永不失败
 *   pnpm sync:friends --only=maowo-space  只同步指定 key（可逗号分隔）
 */

import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();
const FRIENDS_DIR = path.join(ROOT, "src/data/friends");
const AVATAR_DIR = path.join(ROOT, "src/assets/friends");
const MANIFEST_PATH = path.join(ROOT, "src/data/friend-avatars.json");

const AVATAR_SIZE = 160;
const MAX_BYTES = 5 * 1024 * 1024;
const BUILD_MODE = process.argv.includes("--build");
const TIMEOUT_MS = BUILD_MODE ? 8_000 : 15_000;
const RETRIES = BUILD_MODE ? 1 : 2;
const CONCURRENCY = 4;
const USER_AGENT =
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

const onlyArg = process.argv.find((arg) => arg.startsWith("--only="));
const onlyKeys = onlyArg
	? new Set(onlyArg.slice("--only=".length).split(","))
	: null;

/** 由友链 url 生成稳定的 ASCII 文件名，例如 https://maowo.space/ -> maowo-space */
function friendKey(url) {
	const { hostname, pathname } = new URL(url);
	return `${hostname}${pathname}`
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "");
}

/** 根据文件头识别图片格式，识别不了返回 null */
function sniffImage(buf) {
	const hex = buf.subarray(0, 12).toString("hex");
	if (hex.startsWith("89504e470d0a1a0a")) return "png";
	if (hex.startsWith("ffd8ff")) return "jpg";
	if (hex.startsWith("47494638")) return "gif";
	if (
		hex.startsWith("52494646") &&
		buf.subarray(8, 12).toString("latin1") === "WEBP"
	)
		return "webp";
	if (hex.startsWith("00000100")) return "ico";
	if (hex.startsWith("424d")) return "bmp";
	const brand = buf.subarray(4, 12).toString("latin1");
	if (brand === "ftypavif" || brand === "ftypavis") return "avif";
	const head = buf
		.subarray(0, 1024)
		.toString("utf8")
		.replace(/^﻿/, "")
		.trimStart()
		.toLowerCase();
	if (
		(head.startsWith("<svg") || head.startsWith("<?xml")) &&
		head.includes("<svg") &&
		!head.includes("<html")
	) {
		return "svg";
	}
	return null;
}

/** 从 ICO 中挑出最大的一张图；如果它是内嵌 PNG 则返回 PNG 数据 */
function extractPngFromIco(buf) {
	const count = buf.readUInt16LE(4);
	let best = null;
	for (let i = 0; i < count; i++) {
		const entry = 6 + i * 16;
		if (entry + 16 > buf.length) break;
		const width = buf[entry] || 256;
		const bpp = buf.readUInt16LE(entry + 6);
		const size = buf.readUInt32LE(entry + 8);
		const offset = buf.readUInt32LE(entry + 12);
		if (offset + size > buf.length) continue;
		const score = width * 1000 + bpp;
		if (!best || score > best.score) best = { score, size, offset };
	}
	if (!best) return null;
	const data = buf.subarray(best.offset, best.offset + best.size);
	return sniffImage(data) === "png" ? data : null;
}

async function fetchOnce(url, referer) {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
	try {
		const res = await fetch(url, {
			redirect: "follow",
			signal: controller.signal,
			headers: {
				"User-Agent": USER_AGENT,
				Accept:
					"image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
				Referer: referer,
			},
		});
		if (!res.ok) throw new Error(`HTTP ${res.status}`);
		const length = Number(res.headers.get("content-length") || 0);
		if (length > MAX_BYTES) throw new Error(`文件过大 (${length} bytes)`);
		const buf = Buffer.from(await res.arrayBuffer());
		if (buf.length > MAX_BYTES)
			throw new Error(`文件过大 (${buf.length} bytes)`);
		if (buf.length === 0) throw new Error("响应为空");
		return { buf, contentType: res.headers.get("content-type") || "" };
	} finally {
		clearTimeout(timer);
	}
}

async function fetchWithRetry(url, referer) {
	let lastError;
	for (let attempt = 0; attempt <= RETRIES; attempt++) {
		try {
			return await fetchOnce(url, referer);
		} catch (error) {
			lastError = error;
			if (attempt < RETRIES)
				await new Promise((r) => setTimeout(r, 1000 * 2 ** attempt));
		}
	}
	throw lastError;
}

// sharp 按需加载：构建环境装不上时也不影响构建，只是不做格式转换
let sharpPromise;
function loadSharp() {
	sharpPromise ??= import("sharp")
		.then((mod) => mod.default)
		.catch((error) => {
			console.warn(`⚠️  sharp 不可用，头像将原样保存: ${error.message}`);
			return null;
		});
	return sharpPromise;
}

/** 把下载到的数据转换为最终落盘的 { ext, data } */
async function normalize(buf, contentType) {
	const format = sniffImage(buf);
	if (!format) {
		const type = contentType.split(";")[0] || "unknown";
		throw new Error(
			`不是有效图片 (content-type: ${type})，可能被 WAF/人机验证拦截`,
		);
	}

	const source = format === "ico" ? extractPngFromIco(buf) : buf;
	const sharp = await loadSharp();
	if (source && sharp) {
		try {
			const data = await sharp(source, { density: 300, animated: false })
				.resize(AVATAR_SIZE, AVATAR_SIZE, {
					fit: "cover",
					withoutEnlargement: true,
				})
				.webp({ quality: 88 })
				.toBuffer();
			return { ext: "webp", data };
		} catch {
			// sharp 无法解码时回落为原样保存
		}
	}

	// SVG 不原样保存，避免同域下直接打开 SVG 带来的脚本风险
	if (format === "svg" || format === "avif") {
		throw new Error(`${format} 无法转换`);
	}
	return { ext: format, data: buf };
}

async function readJson(file, fallback) {
	try {
		return JSON.parse(await readFile(file, "utf8"));
	} catch {
		return fallback;
	}
}

async function loadFriends() {
	const files = (await readdir(FRIENDS_DIR)).filter((f) => f.endsWith(".json"));
	const friends = [];
	for (const file of files) {
		const friend = await readJson(path.join(FRIENDS_DIR, file), null);
		if (!friend?.name || !friend?.url) {
			console.warn(`⚠️  跳过 ${file}：缺少 name 或 url`);
			continue;
		}
		friends.push({ ...friend, file, key: friendKey(friend.url) });
	}
	return friends;
}

async function runPool(items, worker) {
	const queue = [...items];
	await Promise.all(
		Array.from({ length: Math.min(CONCURRENCY, queue.length) }, async () => {
			while (queue.length) await worker(queue.shift());
		}),
	);
}

async function main() {
	await mkdir(AVATAR_DIR, { recursive: true });
	const friends = await loadFriends();
	const oldManifest = await readJson(MANIFEST_PATH, {});
	const manifest = {};
	const existingFiles = new Set(await readdir(AVATAR_DIR));
	const results = { updated: [], unchanged: [], cached: [], placeholder: [] };

	await runPool(friends, async (friend) => {
		const cached = oldManifest[friend.url];
		const cachedExists = cached && existingFiles.has(cached.file);
		const keep = (reason) => {
			if (cachedExists) {
				manifest[friend.url] = cached;
				results.cached.push(`${friend.name}: ${reason}`);
			} else {
				results.placeholder.push(`${friend.name}: ${reason}`);
			}
		};

		if (onlyKeys && !onlyKeys.has(friend.key)) {
			if (cachedExists) manifest[friend.url] = cached;
			return;
		}
		if (!friend.avatar || !/^https?:\/\//i.test(friend.avatar)) {
			keep("avatar 不是 http(s) 地址");
			return;
		}

		try {
			const { buf, contentType } = await fetchWithRetry(
				friend.avatar,
				friend.url,
			);
			const { ext, data } = await normalize(buf, contentType);
			const file = `${friend.key}.${ext}`;
			const hash = createHash("sha256").update(data).digest("hex").slice(0, 16);

			if (cachedExists && cached.file === file && cached.hash === hash) {
				manifest[friend.url] = { ...cached, source: friend.avatar };
				results.unchanged.push(friend.name);
				return;
			}
			if (cachedExists && cached.file !== file) {
				await rm(path.join(AVATAR_DIR, cached.file), { force: true });
			}
			await writeFile(path.join(AVATAR_DIR, file), data);
			manifest[friend.url] = { file, hash, source: friend.avatar };
			results.updated.push(`${friend.name} -> ${file}`);
		} catch (error) {
			const reason =
				error.name === "AbortError"
					? "请求超时"
					: [error.message, error.cause?.code].filter(Boolean).join(" ");
			keep(reason);
		}
	});

	// 清理已经不在友链列表中的头像文件
	const keptFiles = new Set(Object.values(manifest).map((entry) => entry.file));
	for (const file of await readdir(AVATAR_DIR)) {
		if (!keptFiles.has(file)) {
			await rm(path.join(AVATAR_DIR, file), { force: true });
			console.log(`🗑️  删除过期头像 ${file}`);
		}
	}

	const sorted = Object.fromEntries(
		Object.entries(manifest).sort(([a], [b]) => a.localeCompare(b)),
	);
	const nextJson = `${JSON.stringify(sorted, null, "\t")}\n`;
	const prevJson = await readFile(MANIFEST_PATH, "utf8").catch(() => "");
	if (nextJson !== prevJson) await writeFile(MANIFEST_PATH, nextJson);

	const print = (title, list) => {
		if (!list.length) return;
		console.log(`${title} (${list.length})`);
		for (const item of list) console.log(`   - ${item}`);
	};
	print("✅ 已更新", results.updated);
	print("➖ 无变化", results.unchanged);
	print("⚠️  拉取失败，沿用旧缓存", results.cached);
	print("❌ 拉取失败且无缓存，将显示占位图", results.placeholder);
}

main().catch((error) => {
	console.error("❌ 同步友链头像失败:", error);
	// 构建模式下直接使用仓库里已发布的头像继续构建
	if (!BUILD_MODE) process.exit(1);
});
