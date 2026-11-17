import { execSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { hostname, platform } from "node:os";
import path from "node:path";
import { dirname, join } from "node:path";

import { z } from "zod";

import { isDnsIndependentLoopbackUrl } from "@mycadet/service-contracts/remote-web-pairing";

import {
  basetenTokenPath,
  guardianTokenPath,
  resolveConfigDir,
} from "./config";
import { getGatewayUrl, type LockfileAssistant } from "./lockfile-contract";
import { readLockfile } from "./lockfile";
import { loopbackSafeFetch } from "./loopback-fetch";
import { pairDevice } from "./operations/pair";

const guardianTokenRefreshes = new Map<string, Promise<TokenResult>>();

import {
  GuardianTokenFileSchema,
  type GuardianTokenData,
} from "./guardian-contract";

export { GuardianTokenFileSchema, type GuardianTokenData };

/**
 * Persist an assistant's guardian token where every host-seam reader resolves
 * it (`guardianTokenPath`). The per-assistant directory is created 0700 and the
 * file written 0600; chmod after the write covers a pre-existing file whose
 * mode drifted.
 */
export function saveGuardianToken(
  assistantId: string,
  data: GuardianTokenData,
): void {
  const tokenPath = guardianTokenPath(assistantId);
  fs.mkdirSync(path.dirname(tokenPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(tokenPath, JSON.stringify(data, null, 2) + "\n", {
    mode: 0o600,
  });
  fs.chmodSync(tokenPath, 0o600);
}

/**
 * Read a previously persisted guardian token for the given assistant.
 * Returns the parsed token data, or null if the file does not exist or is
 * unreadable.
 */
export function loadGuardianToken(
  assistantId: string,
): GuardianTokenData | null {
  try {
    const parsed = GuardianTokenFileSchema.safeParse(
      JSON.parse(fs.readFileSync(guardianTokenPath(assistantId), "utf-8")),
    );
    if (parsed.success) {
      return parsed.data;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Persist the Baseten sandbox access token a hatch exchanged for an
 * assistant, at {@link basetenTokenPath} under the guardian token's
 * 0600/0700 discipline. Read by the desktop proxy's forward planner — the
 * single credential for reaching that sandbox's gateway.
 */
export function saveBasetenSandboxToken(
  assistantId: string,
  token: string,
  previewToken?: string,
): void {
  const tokenPath = basetenTokenPath(assistantId);
  fs.mkdirSync(path.dirname(tokenPath), { recursive: true, mode: 0o700 });
  const data = JSON.stringify({
    token,
    ...(previewToken ? { previewToken } : {}),
    mintedAt: new Date().toISOString(),
  });
  fs.writeFileSync(tokenPath, data + "\n", { mode: 0o600 });
  fs.chmodSync(tokenPath, 0o600);
}

/** The token file the hatch writes: the sandbox access token, the gateway
 * preview's token when one was minted, plus mint bookkeeping. */
const BasetenTokenFileSchema = z.object({
  token: z.string().min(1),
  previewToken: z.string().min(1).optional(),
  mintedAt: z.string().optional(),
});

/**
 * The gateway preview's token, saved at hatch — the credential the preview
 * edge wants on every request (header for servers, a cookie for browsers
 * after the first open). Undefined on token files that predate the
 * preview. Baseten mints the two tokens differently: the sandbox access
 * token is an API-key EXCHANGE at POST /v1/token (the server sets a 2h
 * expiry), while preview tokens are minted per-preview with a CALLER-set
 * expires_at — which is why this one is the door credential and the
 * sandbox token only feeds the exec HTTP arm.
 */
export function readBasetenPreviewToken(
  assistantId: string,
): string | undefined {
  try {
    const parsed = BasetenTokenFileSchema.safeParse(
      JSON.parse(fs.readFileSync(basetenTokenPath(assistantId), "utf-8")),
    );
    return parsed.success ? parsed.data.previewToken : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Read a saved Baseten sandbox access token. TokenResult-shaped so it drops
 * straight into the paired-forward credential seam: a missing or corrupt
 * file is a 404, never a throw — the proxy surfaces the structured error.
 */
export function readBasetenSandboxToken(assistantId: string): TokenResult {
  try {
    const parsed = BasetenTokenFileSchema.safeParse(
      JSON.parse(fs.readFileSync(basetenTokenPath(assistantId), "utf-8")),
    );
    if (parsed.success) {
      return { ok: true, accessToken: parsed.data.token };
    }
    return {
      ok: false,
      status: 404,
      error:
        "Baseten sandbox token file is missing a token — re-run `cadet hatch --remote baseten`.",
    };
  } catch (err: unknown) {
    if ((err as unknown as { code?: string }).code === "ENOENT") {
      return {
        ok: false,
        status: 404,
        error:
          "No Baseten sandbox token saved for this assistant — re-run `cadet hatch --remote baseten`.",
      };
    }
    return {
      ok: false,
      status: 500,
      error: `Failed to read the Baseten sandbox token: ${err}`,
    };
  }
}

/**
 * The guardian refresh token is long-lived and replayable, so it is only
 * transmitted over a confidential channel: HTTPS, or a host that stays on this
 * machine whatever DNS answers (local dev, or a same-host reverse proxy /
 * tunnel agent). Refreshing against any other plaintext `http://` URL is
 * refused; an on-path attacker could otherwise capture the refresh token and
 * rotate it into fresh credentials.
 *
 * A user-chosen malicious `https://` destination is intentionally out of
 * scope: HTTPS protects the channel, and the access token already goes
 * wherever the configured URL points. This guard targets the
 * plaintext-interception vector.
 */
export function isConfidentialRefreshUrl(gatewayUrl: string): boolean {
  try {
    return (
      new URL(gatewayUrl).protocol === "https:" ||
      // The narrow loopback set, not {@link isLoopbackUrl}: this grants a
      // plaintext channel the trust of an encrypted one, and a reserved
      // `*.localhost` name resolves to whatever DNS says on a resolver that
      // does not implement RFC 6761, which would put the refresh token on the
      // wire to an arbitrary address.
      isDnsIndependentLoopbackUrl(gatewayUrl)
    );
  } catch {
    return false;
  }
}

function isAccessTokenExpired(data: GuardianTokenData): boolean {
  const expiresAt = new Date(data.accessTokenExpiresAt).getTime();
  if (!Number.isFinite(expiresAt)) return true;
  return Date.now() >= expiresAt - 60_000;
}

function isRefreshTokenExpired(data: GuardianTokenData): boolean {
  const expiresAt = new Date(data.refreshTokenExpiresAt).getTime();
  if (!Number.isFinite(expiresAt)) return true;
  return Date.now() >= expiresAt;
}

export type TokenResult =
  | { ok: true; accessToken: string }
  | { ok: false; status: number; error: string };

/** The persisted shape of an assistant's guardian token file. */
/**
 * The guardian access token for an assistant, from its xdg token file —
 * the only argument is the assistant id, everything else is on disk.
 * Baseten sandboxes don't lease guardian tokens: the credential is the
 * sandbox access token the hatch saved beside the lockfile, read straight
 * from disk — no CLI runtime, no mint, no refresh cycle. A missing file
 * surfaces the structured 404 the proxy renders.
 */
export async function getGuardianAccessToken(
  assistantId: string,
): Promise<TokenResult> {
  if (isBasetenAssistant(assistantId)) {
    return Promise.resolve(readBasetenSandboxToken(assistantId));
  }

  let tokenPath: string;
  try {
    tokenPath = guardianTokenPath(assistantId);
  } catch {
    return Promise.resolve({
      ok: false,
      status: 400,
      error: "Invalid assistant ID",
    });
  }

  let raw: string | undefined;
  try {
    raw = fs.readFileSync(tokenPath, "utf-8");
  } catch {
    // Not found at the one canonical location.
  }
  if (raw === undefined) {
    return Promise.resolve({
      ok: false,
      status: 404,
      error: "Guardian token not found",
    });
  }

  let data: GuardianTokenData;
  try {
    data = JSON.parse(raw) as GuardianTokenData;
  } catch {
    return Promise.resolve({
      ok: false,
      status: 500,
      error: "Malformed guardian token file",
    });
  }

  if (!isAccessTokenExpired(data)) {
    return Promise.resolve({ ok: true, accessToken: data.accessToken });
  }

  if (isRefreshTokenExpired(data)) {
    return Promise.resolve({
      ok: false,
      status: 401,
      error:
        "Guardian token expired. Re-run `cadet hatch`, `cadet wake`, or `cadet pair`.",
    });
  }

  const existingRefresh = guardianTokenRefreshes.get(tokenPath);
  if (existingRefresh) {
    return existingRefresh;
  }
  const refresh = refreshToken(assistantId).finally(() => {
    if (guardianTokenRefreshes.get(tokenPath) === refresh) {
      guardianTokenRefreshes.delete(tokenPath);
    }
  });
  guardianTokenRefreshes.set(tokenPath, refresh);
  return refresh;
}

/**
 * Whether the lockfile records this assistant on the Baseten topology —
 * the proxy's credential seam branches on it (sandbox access token file,
 * not a leased guardian bearer).
 */
function isBasetenAssistant(assistantId: string): boolean {
  return (
    readLockfile().assistants.find((a) => a.assistantId === assistantId)
      ?.cloud === "baseten"
  );
}

async function refreshToken(assistantId: string): Promise<TokenResult> {
  const entry = readLockfile().assistants.find(
    (a) => a.assistantId === assistantId,
  );
  if (!entry) {
    return { ok: false, status: 404, error: "Assistant not found" };
  }
  const result = await refreshGuardianTokenResult(
    getGatewayUrl(entry),
    assistantId,
  );
  return result.ok
    ? { ok: true, accessToken: result.token.accessToken }
    : result;
}

// ─── The guardian-token lease ────────────────────────────────────────────
// Pairing IS the lease: the pair operation's transport proves presence
// (host-loopback POST for local, in-container exec for docker), and the
// paired response IS the credential. Every local-topology hatch leases
// after its gateway is up so hosts can import the token instead of
// re-pairing.

/**
 * Parse /v1/pair's device-bound response into the token data the lease
 * persists. The payload speaks the guardian token file's own field names
 * (the gateway's DeviceBoundPairPayload), so the file schema parses it
 * directly — a malformed 200 throws a {@link GuardianLeasePermanentError};
 * it will not fix itself on retry.
 */
export function parseGuardianToken(raw: unknown): GuardianTokenData {
  const parsed = GuardianTokenFileSchema.safeParse(raw);
  if (!parsed.success) {
    throw new GuardianLeasePermanentError(
      `guardian pair returned a malformed token response — ${z.prettifyError(parsed.error)}`,
    );
  }
  return parsed.data;
}

const DEVICE_ID_SALT = "mycadet-host-id";

function getPersistedDeviceIdPath(): string {
  return join(resolveConfigDir(), "device-id");
}

function hashWithSalt(input: string): string {
  return createHash("sha256")
    .update(input + DEVICE_ID_SALT)
    .digest("hex");
}

function getMacOSPlatformUUID(): string | null {
  try {
    const output = execSync(
      "ioreg -rd1 -c IOPlatformExpertDevice | awk '/IOPlatformUUID/{print $3}'",
      { encoding: "utf-8", timeout: 5000, windowsHide: true },
    ).trim();
    const uuid = output.replace(/"/g, "");
    return uuid.length > 0 ? uuid : null;
  } catch {
    return null;
  }
}

function getLinuxMachineId(): string | null {
  try {
    return readFileSync("/etc/machine-id", "utf-8").trim() || null;
  } catch {
    return null;
  }
}

function getWindowsMachineGuid(): string | null {
  try {
    const output = execSync(
      'reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid',
      { encoding: "utf-8", timeout: 5000, windowsHide: true },
    ).trim();
    const match = output.match(/MachineGuid\s+REG_SZ\s+(.+)/);
    return match?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}

export function getOrCreatePersistedDeviceId(): string {
  const path = getPersistedDeviceIdPath();
  try {
    const existing = readFileSync(path, "utf-8").trim();
    if (existing.length > 0) {
      return existing;
    }
  } catch {
    // File doesn't exist yet
  }
  const newId = randomUUID();
  const dir = dirname(path);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  writeFileSync(path, newId + "\n", { mode: 0o600 });
  return newId;
}

/**
 * Compute a stable device identifier matching the native client conventions.
 *
 * - macOS: SHA-256 of IOPlatformUUID + salt
 * - Linux: SHA-256 of /etc/machine-id + salt
 * - Windows: SHA-256 of HKLM MachineGuid + salt
 * - Fallback: persisted random UUID in XDG config
 */
export function computeDeviceId(): string {
  const os = platform();

  if (os === "darwin") {
    const uuid = getMacOSPlatformUUID();
    if (uuid) return hashWithSalt(uuid);
  } else if (os === "linux") {
    const machineId = getLinuxMachineId();
    if (machineId) return hashWithSalt(machineId);
  } else if (os === "win32") {
    const guid = getWindowsMachineGuid();
    if (guid) return hashWithSalt(guid);
  }

  return getOrCreatePersistedDeviceId();
}

function readClientHostname(): string | undefined {
  try {
    return hostname() || undefined;
  } catch {
    return undefined;
  }
}

export class GuardianLeasePermanentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GuardianLeasePermanentError";
  }
}

/**
 * Pair with the assistant's gateway and persist the minted credential —
 * the lease every local-topology hatch runs once its gateway is up.
 * The pair operation's transport proves presence; re-pairing IS the repair.
 * Waiting for the gateway's ready gate is the caller's job (the hatch
 * waits on the assistant before leasing) — the lease itself just pairs.
 */
export async function leaseGuardianToken(
  entry: LockfileAssistant,
): Promise<GuardianTokenData> {
  const assistantId = entry.assistantId;

  const deviceId = computeDeviceId();
  const clientReportedName = readClientHostname();

  const paired = await pairDevice(entry, {
    platform: "cli",
    deviceId,
    clientReportedName,
  });
  if (!paired.ok) throw new Error(paired.error);

  // The pair door already zod-parsed the mint's stdout line.
  const tokenData = paired.response;

  saveGuardianToken(assistantId, tokenData);
  return tokenData;
}

// ─── Guardian-token refresh ──────────────────────────────────────────────

/** Abort the refresh POST if the gateway is slow/unreachable (it's now on the
 *  hot request path, so it must never hang indefinitely). */
const REFRESH_FETCH_TIMEOUT_MS = 15_000;
/** Max time to wait for the per-assistant refresh lock before proceeding. */
const REFRESH_LOCK_WAIT_MS = 10_000;
/** A lock older than this is treated as stale (holder crashed) and stolen. */
const REFRESH_LOCK_STALE_MS = 30_000;
const REFRESH_LOCK_POLL_MS = 100;

function getRefreshLockPath(assistantId: string): string {
  return join(dirname(guardianTokenPath(assistantId)), "refresh.lock");
}

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Best-effort exclusive cross-process lock for a per-assistant token refresh.
 * Created atomically with `wx`; a stale lock (crashed holder) is stolen.
 * Returns true if acquired, false if it timed out (caller proceeds degraded).
 */
async function acquireRefreshLock(lockPath: string): Promise<boolean> {
  mkdirSync(dirname(lockPath), { recursive: true, mode: 0o700 });
  const deadline = Date.now() + REFRESH_LOCK_WAIT_MS;
  for (;;) {
    try {
      const fd = openSync(lockPath, "wx", 0o600);
      writeSync(fd, String(process.pid));
      closeSync(fd);
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") return false;
      try {
        if (Date.now() - statSync(lockPath).mtimeMs > REFRESH_LOCK_STALE_MS) {
          unlinkSync(lockPath); // steal a stale lock, then retry
          continue;
        }
      } catch {
        continue; // lock vanished between open and stat — retry
      }
      if (Date.now() >= deadline) return false;
      await delay(REFRESH_LOCK_POLL_MS);
    }
  }
}

function releaseRefreshLock(lockPath: string): void {
  try {
    unlinkSync(lockPath);
  } catch {
    /* already released/stolen */
  }
}

/**
 * True when a stored guardian token has reached its renewal point: now is
 * at/after `refreshAfter` (preferred) or `accessTokenExpiresAt`. Used to gate
 * refresh so a forged/synthetic 401 on a still-valid token can't coax out the
 * long-lived refresh credential. Unparseable timestamps → not due.
 */
export function guardianTokenDueForRenewal(token: GuardianTokenData): boolean {
  const raw = token.refreshAfter || token.accessTokenExpiresAt;
  const at = new Date(raw).getTime();
  if (!Number.isFinite(at)) {
    return false;
  }
  return at <= Date.now();
}

export type GuardianTokenRefreshResult =
  | { ok: true; token: GuardianTokenData }
  | { ok: false; status: number; error: string };

function failureChainText(error: unknown): string {
  const parts: string[] = [];
  let current: unknown = error;
  for (let i = 0; i < 4 && current; i++) {
    if (current instanceof Error) {
      parts.push(current.name, current.message);
      if ("code" in current && current.code != null) {
        parts.push(String(current.code));
      }
      current = current.cause;
      continue;
    }
    if (current && typeof current === "object") {
      const record = current as {
        code?: unknown;
        message?: unknown;
        cause?: unknown;
        name?: unknown;
      };
      if (record.name != null) {
        parts.push(String(record.name));
      }
      if (record.message != null) {
        parts.push(String(record.message));
      }
      if (record.code != null) {
        parts.push(String(record.code));
      }
      current = record.cause;
      continue;
    }
    break;
  }
  return parts.join(" ").toLowerCase();
}

function isTimeoutLikeError(error: unknown): boolean {
  if (error instanceof Error) {
    if (error.name === "TimeoutError" || error.name === "AbortError") {
      return true;
    }
  }
  const haystack = failureChainText(error);
  return (
    haystack.includes("timeout") ||
    haystack.includes("etimedout") ||
    haystack.includes("und_err_connect_timeout")
  );
}

function isUnreachableGatewayError(error: unknown): boolean {
  const haystack = failureChainText(error);
  return (
    haystack.includes("econnrefused") ||
    haystack.includes("econnreset") ||
    haystack.includes("enotfound") ||
    haystack.includes("ehostunreach") ||
    haystack.includes("enetunreach") ||
    haystack.includes("und_err_socket") ||
    haystack.includes("fetch failed") ||
    haystack.includes("unable to connect") ||
    haystack.includes("failed to connect")
  );
}

function classifyRefreshThrownError(
  error: unknown,
): GuardianTokenRefreshResult {
  // A malformed 200 body throws from parseGuardianToken: the gateway
  // answered, so this is its contract that's broken — 502, not 500.
  if (error instanceof GuardianLeasePermanentError) {
    return {
      ok: false,
      status: 502,
      error: "Assistant gateway returned a malformed token refresh response",
    };
  }
  if (isTimeoutLikeError(error)) {
    return {
      ok: false,
      status: 504,
      error: "Guardian token refresh timed out",
    };
  }
  if (isUnreachableGatewayError(error)) {
    return {
      ok: false,
      status: 503,
      error: "Assistant gateway is unreachable",
    };
  }
  return {
    ok: false,
    status: 500,
    error: "Failed to refresh guardian token",
  };
}

function classifyRefreshHttpStatus(status: number): GuardianTokenRefreshResult {
  // The guardian refresh route uses 403 for revoked, reused, or
  // device-mismatched tokens. That is a spent credential, not a
  // loopback-boundary refusal, so hosts treat it as 401.
  if (status === 401 || status === 403) {
    return {
      ok: false,
      status: 401,
      error: "Failed to refresh guardian token",
    };
  }
  if (status >= 500) {
    return {
      ok: false,
      status,
      error: `Assistant gateway rejected the token refresh (${status})`,
    };
  }
  return {
    ok: false,
    status,
    error: `Assistant gateway rejected the token refresh (${status})`,
  };
}

/**
 * Call POST /v1/guardian/refresh on the remote gateway to obtain a new
 * access token using an existing (possibly expired) access token for auth.
 * Returns a structured result so hosts can tell a spent credential (401,
 * including a refresh-endpoint 403 for revoked/reused/device-mismatched
 * tokens) from an unreachable gateway (503) instead of collapsing both
 * to null. 403 is reserved for a local confidentiality refusal (insecure
 * URL). Loopback and paired-token refusals are also 403, and they are
 * decided on the host before this refresh runs.
 *
 * Concurrency-safe: the gateway rotates refresh tokens and treats reuse of an
 * already-rotated token as replay (revoking the whole token family), so two
 * processes (e.g. `cadet message` + `cadet events`) refreshing the same
 * stored token at once would self-revoke and force re-pairing. We serialize on
 * a per-assistant lock and, once held, re-read the stored token: if another
 * process already rotated it while we waited, we return that fresh token
 * instead of replaying our now-stale refresh token.
 */
export async function refreshGuardianTokenResult(
  gatewayUrl: string,
  assistantId: string,
): Promise<GuardianTokenRefreshResult> {
  // Never send the long-lived refresh token over a non-loopback plaintext URL.
  if (!isConfidentialRefreshUrl(gatewayUrl)) {
    console.warn(
      `Refusing to refresh the guardian token over an insecure URL (${gatewayUrl}). ` +
        "The refresh token is only sent over https or a loopback address: " +
        "use an https URL, e.g. a tunnel, or connect over loopback.",
    );
    return {
      ok: false,
      status: 403,
      error: "Refusing to refresh the guardian token over an insecure URL",
    };
  }

  const before = loadGuardianToken(assistantId);
  if (!before) {
    return {
      ok: false,
      status: 404,
      error: "Guardian token not found",
    };
  }

  // Gateway persists expiresAt as epoch-ms numbers; Date.parse("1234567890000")
  // returns NaN. new Date() accepts both ISO strings and epoch-ms numbers.
  const refreshExpiry = new Date(before.refreshTokenExpiresAt).getTime();
  if (!Number.isFinite(refreshExpiry) || refreshExpiry <= Date.now()) {
    return {
      ok: false,
      status: 401,
      error: "Guardian refresh token expired",
    };
  }

  const lockPath = getRefreshLockPath(assistantId);
  const locked = await acquireRefreshLock(lockPath);
  try {
    // Re-read under the lock: a concurrent process may have rotated the token
    // while we waited. If the stored refresh token changed, ours is now stale
    // (replaying it would trip reuse-detection). Use the fresh token instead.
    const current = loadGuardianToken(assistantId);
    if (current && current.refreshToken !== before.refreshToken) {
      return { ok: true, token: current };
    }

    // We did NOT acquire the lock (another process is likely mid-refresh) and
    // the stored token hasn't been rotated yet. Do NOT call the gateway: our
    // refresh token may be the one the winner is rotating right now, and
    // replaying a rotated token revokes the whole family (forcing re-pair).
    // Surface a retryable failure so the next attempt can pick up the
    // winner's persisted token.
    if (!locked) {
      return {
        ok: false,
        status: 503,
        error: "Guardian token refresh is already in progress",
      };
    }

    const tokenData = current ?? before;

    const response = await loopbackSafeFetch(
      `${gatewayUrl}/v1/guardian/refresh`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${tokenData.accessToken}`,
        },
        body: JSON.stringify({
          refreshToken: tokenData.refreshToken,
          // The refresh token is device-bound; send the device id used at init
          // (falling back to a fresh computation for tokens persisted before the
          // field was stored) so the gateway can verify the binding.
          deviceId: tokenData.deviceId || computeDeviceId(),
        }),
        signal: AbortSignal.timeout(REFRESH_FETCH_TIMEOUT_MS),
      },
    );
    if (!response.ok) {
      return classifyRefreshHttpStatus(response.status);
    }

    // The refresh endpoint answers with the full guardian credential
    // contract — the same shape the pairing mint emits — so one schema
    // parses the credential from mint to rotation to token file. A
    // malformed body throws and the surrounding catch classifies it.
    const refreshed = parseGuardianToken(await response.json());
    saveGuardianToken(assistantId, refreshed);
    return { ok: true, token: refreshed };
  } catch (error) {
    return classifyRefreshThrownError(error);
  } finally {
    if (locked) {
      releaseRefreshLock(lockPath);
    }
  }
}

/** Convenience wrapper around {@link refreshGuardianTokenResult}. */
export async function refreshGuardianToken(
  gatewayUrl: string,
  assistantId: string,
): Promise<GuardianTokenData | null> {
  const result = await refreshGuardianTokenResult(gatewayUrl, assistantId);
  return result.ok ? result.token : null;
}
