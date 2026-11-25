/**
 * `cadet devices [name]` and `cadet devices revoke <hashedDeviceId> [name] [--yes]`
 *
 * Host-side of pairing lifecycle: list and revoke the devices paired to a
 * local or Docker assistant. Runs the gateway's own `devices list --json` and
 * `devices revoke <id>` commands, the same way `cadet pair` runs
 * `gateway pairing mint`. The gateway only ever stores the HASHED device id,
 * so list returns and revoke accepts the same `hashedDeviceId` (the raw device
 * id is never persisted anywhere).
 */

import { createHash } from "node:crypto";
import { hostname } from "node:os";

import { Command } from "commander";

import {
  cliCommand,
  DeviceRecord,
  getAssistantDisplayName,
  findAssistant,
  loadGuardianToken,
  parseDeviceRecords,
  runGatewayDevicesCommand,
} from "@mycadet/local-mode";
import {
  isDockerEntry,
  isLocalEntry,
  type DockerAssistant,
  type LocalAssistant,
  type LockfileAssistant,
} from "@mycadet/local-mode/contract";
import type { GuardianTokenData } from "@mycadet/local-mode";
import { computeDeviceId } from "@mycadet/local-mode";
import {
  canPromptForConfirmation,
  confirmAction,
} from "../lib/confirm-action.js";

type HostAssistant = LocalAssistant | DockerAssistant;

/**
 * Narrow to an assistant whose gateway runs on this machine, or exit with a
 * helpful error.
 */
function requireHostAssistant(entry: LockfileAssistant): HostAssistant {
  if (isLocalEntry(entry) || isDockerEntry(entry)) return entry;
  console.error(
    `Error: no local gateway found for '${getAssistantDisplayName(entry)}'. \`cadet devices\` runs on the machine hosting a local or Docker assistant.`,
  );
  process.exit(1);
}

/** Run the gateway's `devices` command, or exit with its error. */
async function gatewayDevices(
  entry: HostAssistant,
  args: string[],
): Promise<string> {
  try {
    return await runGatewayDevicesCommand(entry, args);
  } catch (err) {
    console.error(
      `Error: the gateway's devices command failed for '${getAssistantDisplayName(entry)}': ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
    process.exit(1);
  }
}

/**
 * The hashed device id the gateway stores for THIS machine's own guardian
 * credential (`leaseGuardianToken` registers it device-bound as
 * sha256(deviceId)). The gateway's row hashes the deviceId the token was
 * leased with, so prefer the stored token's deviceId and fall back to the
 * current machine id for tokens persisted before the field was stored. It
 * shows up in `/v1/devices` next to remotely paired devices; revoking it
 * locks this host out of its own assistant until guardian repair.
 */
function currentHostHashedDeviceId(token?: GuardianTokenData | null): string {
  const deviceId = token?.deviceId || computeDeviceId();
  return createHash("sha256").update(deviceId).digest("hex");
}

/**
 * The local guardian token.json IS a paired device even when the gateway has
 * no record of it (fresh gateway DB, a lease that predates device tracking).
 * Rebuild the row it would have — same identity the gateway would have
 * stored — so it always shows up in `cadet devices` and stays revocable.
 */
function localHostDeviceRow(
  token: GuardianTokenData,
  hashedDeviceId: string,
): DeviceRecord {
  const leasedAtMs = Date.parse(token.leasedAt);
  return {
    hashedDeviceId,
    platform: "cli",
    issuedAt: Number.isFinite(leasedAtMs) ? leasedAtMs : null,
    expiresAt: null,
    lastUsedAt: null,
    pairingUserAgent: null,
    clientReportedName: hostname(),
    isCurrentHost: true,
  };
}

/** Format an epoch-ms timestamp as ISO, or a placeholder when absent. */
function formatTimestamp(ms: number | null, absent: string): string {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return absent;
  return new Date(ms).toISOString();
}

async function listDevices(
  entry: HostAssistant,
  jsonOutput: boolean,
): Promise<void> {
  const displayName = getAssistantDisplayName(entry);

  // The JSON document is the command's last stdout line.
  const stdout = await gatewayDevices(entry, ["list", "--json"]);
  const listed = parseDeviceRecords(stdout.split("\n").pop() ?? "");
  if (!listed) {
    console.error(
      `Error: the gateway gave unexpected output listing devices for '${displayName}'.`,
    );
    process.exit(1);
  }

  const token = loadGuardianToken(entry.assistantId);
  const hostHash = currentHostHashedDeviceId(token);
  const devices = listed.map((device) =>
    device.hashedDeviceId === hostHash
      ? { ...device, isCurrentHost: true as const }
      : device,
  );

  // The local guardian token.json IS a paired device even when the gateway
  // has no record of it (fresh gateway DB, lease predating device tracking):
  // synthesize the row it would have so it stays visible and revocable here.
  if (token && !devices.some((device) => device.hashedDeviceId === hostHash)) {
    devices.push(localHostDeviceRow(token, hostHash));
  }

  if (jsonOutput) {
    console.log(JSON.stringify({ devices }));
    return;
  }

  if (devices.length === 0) {
    console.log(`No devices are paired to ${displayName}.`);
    return;
  }

  console.log(`Devices paired to ${getAssistantDisplayName(entry)}:`);
  console.log("");
  for (const device of devices) {
    console.log(`  ${device.hashedDeviceId}`);
    console.log(`    platform:   ${device.platform}`);
    console.log(
      `    name:       ${device.clientReportedName || "not reported"}`,
    );
    console.log(`    user agent: ${device.pairingUserAgent || "not recorded"}`);
    console.log(`    issued:     ${formatTimestamp(device.issuedAt, "—")}`);
    console.log(`    expires:    ${formatTimestamp(device.expiresAt, "—")}`);
    console.log(
      `    last used:  ${formatTimestamp(device.lastUsedAt, "never")}`,
    );
    if (device.isCurrentHost) {
      console.log(
        "    this machine's host credential; revoking locks this host out until guardian repair",
      );
    }
    console.log("");
  }
  console.log(
    `${devices.length} device(s). Revoke one with: cadet devices revoke <hashedDeviceId>`,
  );
}

async function revokeDevice(
  entry: HostAssistant,
  hashedDeviceId: string,
  yes: boolean,
  jsonOutput: boolean,
): Promise<void> {
  const displayName = getAssistantDisplayName(entry);

  if (jsonOutput && !yes) {
    console.error(
      "Error: --json requires --yes; the revoke confirmation prompt would corrupt JSON stdout.",
    );
    process.exit(1);
  }

  // Print the resolved identity before acting (cli/AGENTS.md). In --json mode
  // it goes to stderr so stdout stays a single JSON document.
  const printIdentity = jsonOutput ? console.error : console.log;
  printIdentity("Device to revoke:");
  printIdentity(`  Assistant: ${getAssistantDisplayName(entry)}`);
  printIdentity(`  Device:    ${hashedDeviceId}`);
  printIdentity("");

  // Warn (don't block; recoverable via guardian repair) when the target is
  // this machine's own host credential. --json is app-driven; the UI disables
  // the host row, so the warning stays out of automation transcripts.
  const localToken = loadGuardianToken(entry.assistantId);
  if (!jsonOutput && hashedDeviceId === currentHostHashedDeviceId(localToken)) {
    console.error(
      "Warning: this is this machine's own host credential. Revoking it locks this host out of the assistant until guardian repair.",
    );
    console.error("");
  }

  if (!yes) {
    if (!canPromptForConfirmation()) {
      console.error(
        "Error: Refusing to revoke without confirmation in a non-interactive terminal.",
      );
      console.error("Re-run with --yes to confirm from automation.");
      process.exit(1);
    }
    const confirmed = await confirmAction(
      "Press Enter to revoke, or Esc/q to cancel: ",
    );
    if (!confirmed) {
      console.log("Revoke cancelled.");
      process.exit(1);
    }
  }

  await gatewayDevices(entry, ["revoke", hashedDeviceId]);

  if (jsonOutput) {
    console.log(
      JSON.stringify({
        ok: true,
        hashedDeviceId,
        assistantId: entry.assistantId,
      }),
    );
    return;
  }

  console.log(
    `Revoked device ${hashedDeviceId} from ${displayName}. Its tokens are invalidated; that machine must re-pair to reconnect.`,
  );
}

/** Find the named (or active) assistant and require it to be hosted here, or exit. */
function resolveHostAssistant(nameArg: string | undefined): HostAssistant {
  const entry = findAssistant(nameArg);
  if (!entry) {
    console.error(
      nameArg
        ? `No assistant found with name or ID '${nameArg}'.`
        : "No assistant found. Run 'cadet hatch' first.",
    );
    process.exit(1);
  }
  return requireHostAssistant(entry);
}

const DESCRIPTION = "List or revoke devices paired to a local assistant";
const NAME_HELP =
  "Name or id of the local assistant, defaults to the active one";

export function registerDevicesCommand(program: Command): void {
  const devicesCommand = program
    .command("devices")
    .description(DESCRIPTION)
    .argument("[name]", NAME_HELP)
    .option("--json", "Print machine-readable JSON on stdout")
    .addHelpText(
      "after",
      `
Lists the devices paired to a local or Docker assistant, or revokes one by its
hashed id. Runs on the machine that hosts the assistant.

Examples:
  $ ${cliCommand()} devices
  $ ${cliCommand()} devices my-desk
  $ ${cliCommand()} devices revoke 3f9a1c...
  $ ${cliCommand()} devices revoke 3f9a1c... my-desk --yes`,
    )
    .action(async (name: string | undefined, opts: { json?: boolean }) => {
      await listDevices(resolveHostAssistant(name), opts.json ?? false);
    });

  devicesCommand
    .command("revoke")
    .description("Revoke a paired device by its hashed id")
    .argument(
      "<hashedDeviceId>",
      "The device's hashed id (copy it from the list output)",
    )
    .argument("[name]", NAME_HELP)
    .option("--yes", "Skip the confirmation prompt (for automation)")
    .option("--json", "Print machine-readable JSON on stdout (requires --yes)")
    .action(
      async (
        hashedDeviceId: string,
        name: string | undefined,
        _opts: unknown,
        command: Command,
      ) => {
        // `devices` declares --json too and claims it wherever it appears.
        const opts = command.optsWithGlobals<{
          yes?: boolean;
          json?: boolean;
        }>();
        await revokeDevice(
          resolveHostAssistant(name),
          hashedDeviceId,
          opts.yes ?? false,
          opts.json ?? false,
        );
      },
    );
}

/**
 * Compat runner for the devices suites: the tests set process.argv and call
 * `devices()` the way the pre-commander entry did. Builds the devices
 * command standalone and parses the argv after the command word.
 */
export const devices = Object.assign(
  async function devices(): Promise<void> {
    const program = new Command();
    program.name(cliCommand());
    registerDevicesCommand(program);
    await program.parseAsync(["devices", ...process.argv.slice(3)], {
      from: "user",
    });
  },
  { description: DESCRIPTION },
);
