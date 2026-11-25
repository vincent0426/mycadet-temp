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

const testDir = mkdtempSync(join(tmpdir(), "cli-logs-test-"));
const originalArgv = [...process.argv];
const originalConfigHome = process.env.XDG_CONFIG_HOME;
const instanceDir = join(testDir, "mine");

let consoleLogSpy: ReturnType<typeof spyOn>;

beforeEach(() => {
  process.env.XDG_CONFIG_HOME = testDir;
  mkdirSync(join(testDir, "cadet"), { recursive: true });
  writeFileSync(
    resolveLockfilePath(),
    JSON.stringify({ assistants: [] }) + "\n",
  );
  makeEntry({ assistantId: "mine", instanceDir });

  // The shared CLI log carries other assistants' lines.
  mkdirSync(resolveLogDir(), { recursive: true });
  writeFileSync(
    join(resolveLogDir(), "hatch.log"),
    "2026-01-01T00:00:01.000Z [credential-executor] someone else's line\n",
  );

  mkdirSync(join(instanceDir, "logs"), { recursive: true });
  writeFileSync(
    join(instanceDir, "logs", "assistant-stdout.log"),
    "2026-01-01T00:00:01.000Z [daemon] daemon one\n" +
      "2026-01-01T00:00:03.000Z [daemon] daemon two\n",
  );
  writeFileSync(
    join(instanceDir, "logs", "gateway-stdout.log"),
    "2026-01-01T00:00:02.000Z [gateway] gateway one\n",
  );

  consoleLogSpy = spyOn(console, "log").mockImplementation(() => {});
});

afterEach(() => {
  process.argv = [...originalArgv];
  consoleLogSpy.mockRestore();
  rmSync(join(testDir, "cadet"), { recursive: true, force: true });
  rmSync(instanceDir, { recursive: true, force: true });
});

afterAll(() => {
  rmSync(testDir, { recursive: true, force: true });
  if (originalConfigHome !== undefined) {
    process.env.XDG_CONFIG_HOME = originalConfigHome;
  } else {
    delete process.env.XDG_CONFIG_HOME;
  }
});

function printed(): string[] {
  return consoleLogSpy.mock.calls.map((call: unknown[]) => String(call[0]));
}

describe("logs for a local assistant", () => {
  test("shows that assistant's own daemon and gateway lines in time order", async () => {
    process.argv = ["bun", "cadet", "logs", "mine"];
    await logs();
    expect(printed()).toEqual([
      "2026-01-01T00:00:01.000Z [daemon] daemon one",
      "2026-01-01T00:00:02.000Z [gateway] gateway one",
      "2026-01-01T00:00:03.000Z [daemon] daemon two",
    ]);
  });

  test("--service and --tail apply across both files", async () => {
    process.argv = ["bun", "cadet", "logs", "mine", "--service", "daemon"];
    await logs();
    expect(printed()).toEqual([
      "2026-01-01T00:00:01.000Z [daemon] daemon one",
      "2026-01-01T00:00:03.000Z [daemon] daemon two",
    ]);

    consoleLogSpy.mockClear();
    process.argv = ["bun", "cadet", "logs", "mine", "--tail", "1"];
    await logs();
    expect(printed()).toEqual(["2026-01-01T00:00:03.000Z [daemon] daemon two"]);
  });
});
