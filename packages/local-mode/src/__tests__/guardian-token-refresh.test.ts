import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  getGuardianAccessToken,
  loadGuardianToken,
  saveGuardianToken,
  type GuardianTokenData,
} from "../guardian-token";
import { saveLockfileAssistant } from "../lockfile";

const FUTURE = new Date(Date.now() + 60 * 60 * 1000).toISOString();
const PAST = new Date(Date.now() - 60_000).toISOString();

function makeTokenData(over: Partial<GuardianTokenData>): GuardianTokenData {
  return {
    guardianPrincipalId: "principal",
    accessToken: "access",
    accessTokenExpiresAt: PAST,
    refreshToken: "refresh",
    refreshTokenExpiresAt: FUTURE,
    refreshAfter: PAST,
    deviceId: "device",
    leasedAt: new Date().toISOString(),
    ...over,
  };
}

describe("getGuardianAccessToken refresh", () => {
  let home: string;
  let gateway: ReturnType<typeof Bun.serve>;
  let gatewayStatus: number;
  let refreshBodies: unknown[];

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-refresh-"));
    process.env.XDG_CONFIG_HOME = home;
    gatewayStatus = 200;
    refreshBodies = [];
    gateway = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: async (req) => {
        if (new URL(req.url).pathname !== "/v1/guardian/refresh") {
          return new Response("not found", { status: 404 });
        }
        refreshBodies.push(await req.json());
        if (gatewayStatus !== 200) {
          return new Response("refused", { status: gatewayStatus });
        }
        return Response.json(
          makeTokenData({
            accessToken: "access-rotated",
            accessTokenExpiresAt: FUTURE,
            refreshToken: "refresh-rotated",
            refreshAfter: FUTURE,
          }),
        );
      },
    });
    saveLockfileAssistant({
      assistantId: "asst-1",
      cloud: "local",
      instanceDir: home,
      port: gateway.port,
    });
    saveGuardianToken("asst-1", makeTokenData({}));
  });

  afterEach(() => {
    gateway.stop(true);
    Reflect.deleteProperty(process.env, "XDG_CONFIG_HOME");
    fs.rmSync(home, { recursive: true, force: true });
  });

  test("an expired access token is renewed against the assistant's gateway", async () => {
    expect(await getGuardianAccessToken("asst-1")).toEqual({
      ok: true,
      accessToken: "access-rotated",
    });
    expect(refreshBodies).toEqual([
      { refreshToken: "refresh", deviceId: "device" },
    ]);
    expect(loadGuardianToken("asst-1")?.refreshToken).toBe("refresh-rotated");
  });

  test("a gateway refusal is a spent credential", async () => {
    gatewayStatus = 401;

    const result = await getGuardianAccessToken("asst-1");

    expect(result.ok).toBe(false);
    expect((result as { status: number }).status).toBe(401);
  });
});
