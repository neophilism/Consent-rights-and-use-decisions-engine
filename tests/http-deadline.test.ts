import test from "node:test";
import assert from "node:assert/strict";
import { createParticipantHandler } from "../src/participant-http.ts";
import { setup, participant, response } from "./participant-fixture.ts";
const origin = "https://private.example",
  csrf = "s".repeat(40);
const block = () => {
  const end = performance.now() + 50;
  while (performance.now() < end) {}
};
for (const mode of ["session", "accept"] as const)
  test(`late blocked authentication cannot admit participant ${mode}`, async (t) => {
    const f = await setup(t);
    const command = await response(f.registry);
    let signal: AbortSignal | undefined;
    const handler = createParticipantHandler(
      f.registry,
      {
        authenticate: async (_m, s) => {
          signal = s;
          block();
          return { context: participant, csrfToken: csrf };
        },
      },
      {
        tenantId: participant.tenantId,
        projectId: participant.projectId,
        origin,
        authenticationTimeoutMs: 10,
      },
    );
    const r =
      mode === "session"
        ? new Request(origin + "/participant/session", { headers: { origin } })
        : new Request(origin + "/participant/respond", {
            method: "POST",
            headers: {
              origin,
              "content-type": "application/json",
              "x-csrf-token": csrf,
            },
            body: JSON.stringify({ commandId: "accept", input: command }),
          });
    assert.equal((await handler(r)).status, 503);
    assert.equal(signal?.aborted, true);
    assert.equal(
      (await f.registry.reviewOffer(participant, "offer")).offer.status,
      "offered",
    );
  });
test("blocked body read cannot accept consent before a delayed timeout; timely auth signals close", async (t) => {
  const f = await setup(t);
  const command = await response(f.registry);
  let signal: AbortSignal | undefined;
  const handler = createParticipantHandler(
    f.registry,
    {
      authenticate: async (_m, s) => {
        signal = s;
        return { context: participant, csrfToken: csrf };
      },
    },
    {
      tenantId: participant.tenantId,
      projectId: participant.projectId,
      origin,
      bodyTimeoutMs: 10,
    },
  );
  let sent = false;
  const body = new ReadableStream<Uint8Array>(
    {
      pull(q) {
        if (sent) {
          q.close();
          return;
        }
        sent = true;
        block();
        q.enqueue(
          new TextEncoder().encode(
            JSON.stringify({ commandId: "accept", input: command }),
          ),
        );
      },
    },
    { highWaterMark: 0 },
  );
  const r = new Request(origin + "/participant/respond", {
    method: "POST",
    headers: {
      origin,
      "content-type": "application/json",
      "x-csrf-token": csrf,
    },
    body,
    duplex: "half",
  } as RequestInit);
  assert.equal((await handler(r)).status, 408);
  assert.equal(signal?.aborted, true);
  assert.equal(
    (await f.registry.reviewOffer(participant, "offer")).offer.status,
    "offered",
  );
});
