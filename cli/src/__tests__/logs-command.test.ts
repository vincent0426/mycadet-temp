import { resolveLockfilePath, resolveLogDir } from "@mycadet/local-mode";
import {
  afterAll,
  afterEach,
  beforeEach,
  describe,
  expect,
  spyOn,
  test,
} from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { makeEntry } from "./helpers/lockfile-entry.js";

import { logs } from "../commands/logs.js";

const testDir = mkdtempSync(join(tmpdir(), "cli-logs-command-test-"));
const originalArgv = [...process.argv];
const originalConfigHome = process.env.XDG_CONFIG_HOME;

let consoleLogSpy: ReturnType<typeof spyOn>;

beforeEach(() => {
  process.env.XDG_CONFIG_HOME = testDir;
  mkdirSync(join(testDir, "cadet"), { recursive: true });
  writeFileSync(
    resolveLockfilePath(),
    JSON.stringify({ assistants: [] }) + "\n",
  );
  makeEntry({ assistantId: "mine", instanceDir: join(testDir, "mine") });
  mkdirSync(resolveLogDir(), { recursive: true });
  writeFileSync(
    join(resolveLogDir(), "hatch.log"),
    "2026-01-01T00:00:01.000Z [daemon] one\n" +
      "2026-01-01T00:00:02.000Z [gateway] two\n",
  );
  consoleLogSpy = spyOn(console, "log").mockImplementation(() => {});
});

afterEach(() => {
  process.argv = [...originalArgv];
  consoleLogSpy.mockRestore();
  rmSync(join(testDir, "cadet"), { recursive: true, force: true });
});

afterAll(() => {
  rmSync(testDir, { recursive: true, force: true });
  if (originalConfigHome !== undefined) {
    process.env.XDG_CONFIG_HOME = originalConfigHome;
  } else {
    delete process.env.XDG_CONFIG_HOME;
  }
});

/** Run logs() with the given args, capturing stdout/stderr writes and exit. */
async function run(
  args: string[],
): Promise<{ code: unknown; stdout: string; stderr: string }> {
  process.argv = ["bun", "cadet", "logs", ...args];
  const stdout: string[] = [];
  const stderr: string[] = [];
  const out = spyOn(process.stdout, "write").mockImplementation((chunk) => {
    stdout.push(String(chunk));
    return true;
  });
  const err = spyOn(process.stderr, "write").mockImplementation((chunk) => {
    stderr.push(String(chunk));
    return true;
  });
  const exit = spyOn(process, "exit").mockImplementation((code) => {
    throw new Error(`exit:${code}`);
  });
  let code: unknown = "returned";
  try {
    await logs();
  } catch (error) {
    code = error instanceof Error ? error.message : error;
  } finally {
    out.mockRestore();
    err.mockRestore();
    exit.mockRestore();
  }
  return { code, stdout: stdout.join(""), stderr: stderr.join("") };
}

function printed(): string[] {
  return consoleLogSpy.mock.calls.map((call: unknown[]) => String(call[0]));
}

describe("logs arguments", () => {
  test("--help lists the name and every option", async () => {
    const result = await run(["--help"]);
    expect(result.code).toBe("exit:0");
    expect(result.stdout).toContain("Usage: cadet logs [options] [name]");
    for (const flag of [
      "-f, --follow",
      "-n, --tail <N>",
      "-t, --timestamps",
      "--since <time>",
      "--until <time>",
      "-s, --service <name>",
    ]) {
      expect(result.stdout).toContain(flag);
    }
  });

  test("--tail=N works like --tail N", async () => {
    const result = await run(["mine", "--tail=1"]);
    expect(result.code).toBe("returned");
    expect(printed()).toEqual(["2026-01-01T00:00:02.000Z [gateway] two"]);
  });

  test("--tail rejects a value that isn't a non-negative integer", async () => {
    const result = await run(["mine", "--tail", "abc"]);
    expect(result.code).toBe("exit:1");
    expect(result.stderr).toContain("non-negative integer");
  });

  test("an unknown option is refused", async () => {
    const result = await run(["mine", "--bogus"]);
    expect(result.code).toBe("exit:1");
    expect(result.stderr).toContain("unknown option '--bogus'");
  });
});
