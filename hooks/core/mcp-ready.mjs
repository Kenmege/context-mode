/**
 * MCP readiness sentinel — checks if MCP server has started.
 *
 * Server writes sentinel (containing its PID) after connect().
 * Hooks scan live sentinels. A sentinel that names its owner counts only when
 * its `session=` equals this hook's CLAUDE_CODE_SESSION_ID or its `parent=`
 * (the agent that spawned the server) is one of this hook's ancestors, so
 * another session's server does not make this session look ready. PID-only
 * sentinels keep the any-live result (#347).
 *
 * Fix for #347: Claude Code spawns hooks via `bash -c "node ..."` on Linux/WSL2.
 * The intermediate shell makes process.ppid point to a transient bash PID, not
 * Claude Code. Directory-scan + PID liveness probe works regardless of spawn topology.
 *
 * Sentinel path: <tmpRoot>/context-mode-mcp-ready-<MCP_PID>
 * Scan: glob all context-mode-mcp-ready-* files, probe each PID.
 */
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync, statSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SENTINEL_PREFIX = "context-mode-mcp-ready-";

/**
 * Sentinel freshness window (#844). The MCP server refreshes its sentinel's
 * mtime every 30s while alive (see `main()` in src/server.ts). A sentinel
 * touched within this window is treated as a live server even when
 * `process.kill(pid, 0)` cannot see the PID — e.g. a sandbox sharing /tmp
 * across an isolated PID namespace, where the live host PID is invisible.
 * 90s = 3x the server refresh interval, tolerant of scheduler jitter / load.
 */
const SENTINEL_FRESH_MS = 90_000;

/**
 * Resolve the temp root — hardcoded /tmp on Unix to avoid TMPDIR mismatch.
 * Tests may override via CONTEXT_MODE_MCP_SENTINEL_DIR to isolate scan from
 * leftover sentinels in the real /tmp.
 */
export function sentinelDir() {
  const override = process.env.CONTEXT_MODE_MCP_SENTINEL_DIR;
  if (override && override.length > 0) return override;
  return process.platform === "win32" ? tmpdir() : "/tmp";
}

/**
 * Build sentinel path for a given PID.
 * Used by server.ts to write its own sentinel.
 */
export function sentinelPathForPid(pid) {
  return join(sentinelDir(), `${SENTINEL_PREFIX}${pid}`);
}

/**
 * @deprecated Use sentinelPathForPid(process.pid) from server.ts.
 * Kept for backward compat during migration — tests that still
 * write sentinels with process.ppid will work for one release cycle.
 */
export function sentinelPath() {
  return join(sentinelDir(), `${SENTINEL_PREFIX}${process.ppid}`);
}

const HOOK_ANCESTOR_DEPTH = 12;

/**
 * Optional owner lines after the PID: `parent=<agent pid>` and
 * `session=<CLAUDE_CODE_SESSION_ID>`. Both null for a legacy sentinel.
 */
function parseSentinelOwner(raw) {
  let parent = null;
  let session = null;
  const lines = String(raw).split("\n");
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.startsWith("parent=")) {
      const n = parseInt(line.slice("parent=".length), 10);
      if (Number.isInteger(n) && n > 1) parent = n;
    } else if (line.startsWith("session=")) {
      const value = line.slice("session=".length);
      if (value.length > 0) session = value;
    }
  }
  return { parent, session };
}

function splitFields(line) {
  const parts = [];
  let current = "";
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === " " || ch === "\t") {
      if (current.length > 0) {
        parts.push(current);
        current = "";
      }
    } else {
      current += ch;
    }
  }
  if (current.length > 0) parts.push(current);
  return parts;
}

/** ppid from `/proc/<pid>/stat` (comm may contain spaces and parentheses). */
function ppidFromProcStat(stat) {
  const close = stat.lastIndexOf(")");
  if (close < 0) return null;
  let i = close + 1;
  while (i < stat.length && (stat[i] === " " || stat[i] === "\t")) i++;
  while (i < stat.length && stat[i] !== " " && stat[i] !== "\t") i++;
  while (i < stat.length && (stat[i] === " " || stat[i] === "\t")) i++;
  let num = "";
  while (i < stat.length && stat[i] >= "0" && stat[i] <= "9") {
    num += stat[i];
    i++;
  }
  if (num.length === 0) return null;
  const n = parseInt(num, 10);
  return isNaN(n) ? null : n;
}

function readLinuxParentPid(pid) {
  try {
    if (!Number.isInteger(pid) || pid <= 0) return null;
    const parsed = ppidFromProcStat(readFileSync(`/proc/${pid}/stat`, "utf8"));
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Hook ancestor pids, excluding 0 and 1, at most 12 levels.
 * `null` means the walk could not be completed.
 */
function ancestorSetFromParents(startPid, readParent) {
  const set = new Set();
  let pid = startPid;
  for (let level = 0; level < HOOK_ANCESTOR_DEPTH; level++) {
    let parent;
    try {
      parent = readParent(pid);
    } catch {
      return null;
    }
    if (typeof parent !== "number" || isNaN(parent) || parent < 0) return null;
    if (parent === 0 || parent === 1 || parent === pid) break;
    set.add(parent);
    pid = parent;
  }
  return set;
}

/** One `ps -A -o pid=,ppid=` snapshot, then walk. `null` if ps cannot be read. */
function ancestorSetFromPsTable(startPid) {
  let result;
  try {
    result = spawnSync("ps", ["-A", "-o", "pid=,ppid="], {
      encoding: "utf8",
      timeout: 1000,
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    return null;
  }
  if (!result || result.error || result.status !== 0 || typeof result.stdout !== "string") {
    return null;
  }
  const parentOf = new Map();
  for (const line of result.stdout.split("\n")) {
    const parts = splitFields(line);
    if (parts.length < 2) continue;
    const pid = parseInt(parts[0], 10);
    const ppid = parseInt(parts[1], 10);
    if (isNaN(pid) || isNaN(ppid)) continue;
    parentOf.set(pid, ppid);
  }
  if (!parentOf.has(startPid)) return null;
  return ancestorSetFromParents(startPid, (pid) => (
    parentOf.has(pid) ? parentOf.get(pid) : null
  ));
}

function defaultHookAncestorLookup() {
  try {
    if (process.platform === "linux") return ancestorSetFromParents(process.pid, readLinuxParentPid);
    if (process.platform === "darwin") return ancestorSetFromPsTable(process.pid);
    return null;
  } catch {
    return null;
  }
}

/** Tests inject this so session-scope checks never spawn `ps`. */
let hookAncestorLookup = defaultHookAncestorLookup;

export function __setHookAncestorLookupForTests(fn) {
  hookAncestorLookup = typeof fn === "function" ? fn : defaultHookAncestorLookup;
}

function sentinelIsLive(pid, fullPath, now) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    if (err && err.code === "EPERM") return true;
    // ESRCH: PID invisible here. #844 — a shared /tmp across PID namespaces
    // hides a live host PID, so a recently refreshed sentinel stays live.
    let ageMs = Infinity;
    try { ageMs = now - statSync(fullPath).mtimeMs; } catch { /* treat as stale */ }
    if (ageMs < SENTINEL_FRESH_MS) return true;
    try { unlinkSync(fullPath); } catch { /* best effort */ }
    return false;
  }
}

/**
 * True when a live sentinel belongs to this session's server.
 *
 * `CONTEXT_MODE_MCP_READY_SCOPE=global` keeps the historical any-live-sentinel
 * result for hosts that spawn the server outside the agent process tree.
 * Otherwise a sentinel counts when its `session=` matches this hook's
 * CLAUDE_CODE_SESSION_ID (no process lookup needed) or its `parent=` is one of
 * this hook's ancestors. Legacy sentinels (no owner lines) and a failed
 * ancestry lookup stay on the historical result so older servers keep
 * redirecting.
 */
export function isMCPReady() {
  try {
    const sessionScoped = process.env.CONTEXT_MODE_MCP_READY_SCOPE !== "global";
    const dir = sentinelDir();
    const files = readdirSync(dir).filter(f => f.startsWith(SENTINEL_PREFIX));
    const now = Date.now();
    const liveRaw = [];
    for (const f of files) {
      const fullPath = join(dir, f);
      let raw;
      try {
        raw = readFileSync(fullPath, "utf8");
      } catch {
        // Unreadable (torn mid-write) — leave it for the owner / a later scan.
        continue;
      }
      const pid = parseInt(raw, 10);
      if (isNaN(pid)) continue;
      if (!sentinelIsLive(pid, fullPath, now)) continue;
      // Global scope is the pre-session-scope early return: first live sentinel wins.
      if (!sessionScoped) return true;
      liveRaw.push(raw);
    }
    if (liveRaw.length === 0) return false;

    const owners = liveRaw.map(parseSentinelOwner);
    const isLegacy = (o) => o.parent === null && o.session === null;
    // No owner lines → do not spawn ps. Historical any-live result.
    if (owners.every(isLegacy)) return true;

    const hookSession = process.env.CLAUDE_CODE_SESSION_ID;
    if (hookSession && owners.some((o) => o.session === hookSession)) return true;

    if (owners.some((o) => o.parent !== null)) {
      let hookAncestors;
      try {
        hookAncestors = hookAncestorLookup();
      } catch {
        hookAncestors = null;
      }
      // Lookup unavailable → historical any-live result.
      if (hookAncestors == null) return true;
      if (owners.some((o) => o.parent !== null && hookAncestors.has(o.parent))) return true;
    }
    // A legacy sentinel beside owned ones still means "some server we cannot place".
    if (owners.some(isLegacy)) return true;
    // Every live sentinel names an owner and none is this session.
    return false;
  } catch {
    return false;
  }
}
