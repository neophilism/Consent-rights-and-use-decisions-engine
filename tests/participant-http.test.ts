import test from "node:test";
import assert from "node:assert/strict";
import { scoped } from "@accountability/evidence/database";
import type { Database } from "@accountability/evidence/database";
import { PermissionRegistry } from "../src/registry.ts";
import { createParticipantHandler } from "../src/participant-http.ts";
import type { ParticipantAuthentication } from "../src/participant-http.ts";
import type { Context } from "../src/contracts.ts";
import {
  manager,
  participant,
  setup,
  response,
} from "./participant-fixture.ts";

const origin = "https://private.example";
const csrf = "s".repeat(40);
const policy = {
  tenantId: manager.tenantId,
  projectId: manager.projectId,
  origin,
};
const auth: ParticipantAuthentication = {
  authenticate: async () => ({ context: participant, csrfToken: csrf }),
};
function request(
  path: string,
  value?: unknown,
  headers: Record<string, string> = {},
) {
  return new Request(origin + path, {
    method: value === undefined ? "GET" : "POST",
    headers: {
      origin,
      "sec-fetch-site": "same-origin",
      ...(value === undefined
        ? {}
        : { "content-type": "application/json", "x-csrf-token": csrf }),
      ...headers,
    },
    ...(value === undefined ? {} : { body: JSON.stringify(value) }),
  });
}
async function details(value: Response) {
  return JSON.parse(await value.text()) as Record<string, any>;
}

test("HTTP participant review, exact capture, current withdrawal and immutable replay use real registry", async (t) => {
  const { registry, db } = await setup(t);
  const handler = createParticipantHandler(registry, auth, policy);
  const session = await handler(request("/participant/session"));
  assert.equal(session.status, 200);
  assert.equal(session.headers.get("cache-control"), "private, no-store");
  assert.equal(session.headers.get("access-control-allow-origin"), null);
  assert.deepEqual(Object.keys(await details(session)).sort(), [
    "actorId",
    "csrfToken",
    "projectId",
    "tenantId",
  ]);
  const reviewed = await details(
    await handler(request("/participant/offer?offerId=offer")),
  );
  assert.equal(reviewed.responseOpen, true);
  assert.equal(JSON.stringify(reviewed).includes("other-person"), false);
  const envelope = {
    commandId: "http-accept",
    input: {
      offerId: "offer",
      expectedRevision: reviewed.offer.ref.revision,
      reviewDigest: reviewed.reviewDigest,
      response: "accept",
      acknowledged: true,
    },
  };
  const accepted = await handler(request("/participant/respond", envelope));
  assert.equal(accepted.status, 200);
  const captured = await details(accepted);
  assert.equal(captured.status, "accepted");
  assert.equal(
    (await handler(request("/participant/respond", envelope))).status,
    200,
  );
  const withdrawal = {
    commandId: "http-withdraw",
    offerId: "offer",
    expectedConsentRevision: 1,
  };
  const withdrawn = await details(
    await handler(request("/participant/withdraw", withdrawal)),
  );
  assert.equal(withdrawn.ref.revision, 2);
  assert.equal(withdrawn.withdrawnAt, participant.now);
  assert.deepEqual(
    await details(await handler(request("/participant/withdraw", withdrawal))),
    withdrawn,
  );
  assert.equal(
    (await details(await handler(request("/participant/offer?offerId=offer"))))
      .consent.ref.revision,
    2,
  );
  await scoped(db, manager, async (tx) =>
    assert.equal((await tx.list("consent")).length, 1),
  );
});

test("HTTP admission denies cross-origin CSRF, extra query/commands and manager routes before writes", async (t) => {
  const { registry, db } = await setup(t);
  const handler = createParticipantHandler(registry, auth, policy);
  const envelope = { commandId: "accept", input: await response(registry) };
  const cases: [Request, number][] = [
    [
      request("/participant/respond", envelope, {
        origin: "https://foreign.example",
      }),
      403,
    ],
    [
      request("/participant/respond", envelope, {
        "sec-fetch-site": "cross-site",
      }),
      403,
    ],
    [
      request("/participant/respond", envelope, { "x-csrf-token": "wrong" }),
      403,
    ],
    [
      request("/participant/respond", envelope, {
        "x-csrf-token": "x".repeat(40),
      }),
      403,
    ],
    [request("/participant/offer?offerId=offer&offerId=second"), 400],
    [request("/participant/offer?offerId=offer&subjectId=subject"), 400],
    [request("/participant/session?scope=other"), 400],
    [request("/participant/respond", { ...envelope, context: manager }), 400],
    [
      request("/participant/respond", {
        ...envelope,
        input: { ...envelope.input, subjectId: "second-subject" },
      }),
      400,
    ],
    [
      request("/participant/respond", {
        ...envelope,
        input: { ...envelope.input, acknowledged: "true" },
      }),
      400,
    ],
    [request("/participant/createOffer", {}), 404],
    [request("/participant/grantRights", {}), 404],
    [request("/participant/publish", {}), 404],
    [request("/participant/session", {}), 405],
    [
      new Request("https://foreign.example/participant/session", {
        headers: { origin },
      }),
      403,
    ],
  ];
  for (const [req, status] of cases)
    assert.equal((await handler(req)).status, status, req.url);
  await scoped(db, manager, async (tx) =>
    assert.equal((await tx.list("consent")).length, 0),
  );
});

test("HTTP sessions require trusted human participant scope and hide foreign offers identically", async (t) => {
  const { registry } = await setup(t);
  const identities: [Context | null, number][] = [
    [null, 401],
    [manager, 403],
    [{ ...participant, actor: { ...participant.actor, kind: "service" } }, 403],
    [{ ...participant, projectId: "foreign" }, 403],
  ];
  for (const [context, status] of identities) {
    const handler = createParticipantHandler(
      registry,
      {
        authenticate: async () =>
          context === null ? null : { context, csrfToken: csrf },
      },
      policy,
    );
    assert.equal(
      (await handler(request("/participant/session"))).status,
      status,
    );
  }
  const other = {
    ...participant,
    actor: { ...participant.actor, id: "other-person" },
  };
  const handler = createParticipantHandler(
    registry,
    { authenticate: async () => ({ context: other, csrfToken: csrf }) },
    policy,
  );
  const foreign = await details(
    await handler(request("/participant/offer?offerId=offer")),
  );
  assert.deepEqual(
    await details(await handler(request("/participant/offer?offerId=missing"))),
    foreign,
  );
  assert.equal(
    (
      await handler(
        request("/participant/withdraw", {
          commandId: "w",
          offerId: "offer",
          expectedConsentRevision: 1,
        }),
      )
    ).status,
    404,
  );
  const bad = createParticipantHandler(
    registry,
    {
      authenticate: async () => {
        throw new Error("secret token must never appear");
      },
    },
    policy,
  );
  const rejected = await bad(request("/participant/session"));
  assert.equal(rejected.status, 503);
  assert.deepEqual(await details(rejected), {
    error: "authentication_unavailable",
  });
});

test("HTTP body byte, chunk, decoding and media limits reject without state changes", async (t) => {
  const { registry, db } = await setup(t);
  const handler = createParticipantHandler(registry, auth, policy);
  const envelope = { commandId: "accept", input: await response(registry) };
  for (const [req, status] of [
    [
      request("/participant/respond", envelope, {
        "content-type": "text/plain",
      }),
      415,
    ],
    [
      request("/participant/respond", envelope, { "content-encoding": "gzip" }),
      415,
    ],
    [
      request("/participant/respond", envelope, { "content-length": "16385" }),
      413,
    ],
    [
      request("/participant/respond", envelope, { "content-length": "-1" }),
      413,
    ],
    [request("/participant/respond", { padding: "x".repeat(17000) }), 413],
    [
      new Request(origin + "/participant/respond", {
        method: "POST",
        headers: {
          origin,
          "x-csrf-token": csrf,
          "content-type": "application/json",
        },
        body: new Uint8Array([0xff]),
      }),
      400,
    ],
  ] as [Request, number][])
    assert.equal((await handler(req)).status, status);
  let count = 0,
    cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      count++;
      controller.enqueue(new Uint8Array());
    },
    cancel() {
      cancelled = true;
    },
  });
  const streamed = new Request(origin + "/participant/respond", {
    method: "POST",
    headers: {
      origin,
      "x-csrf-token": csrf,
      "content-type": "application/json",
    },
    body: stream,
    duplex: "half",
  } as RequestInit & { duplex: "half" });
  assert.equal((await handler(streamed)).status, 413);
  assert.equal(cancelled, true);
  assert.ok(count <= 4099);
  await scoped(db, manager, async (tx) =>
    assert.equal((await tx.list("consent")).length, 0),
  );
});

test("HTTP authentication/body deadlines and cancellation do not start late mutations", async (t) => {
  const { registry } = await setup(t);
  let authSignal: AbortSignal | undefined;
  const hanging = createParticipantHandler(
    registry,
    {
      authenticate: (_meta, signal) => {
        authSignal = signal;
        return new Promise(() => {});
      },
    },
    { ...policy, authenticationTimeoutMs: 10 },
  );
  assert.equal((await hanging(request("/participant/session"))).status, 503);
  assert.equal(authSignal?.aborted, true);
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({
    pull() {
      return new Promise(() => {});
    },
    cancel() {
      cancelled = true;
      return new Promise(() => {});
    },
  });
  const handler = createParticipantHandler(registry, auth, {
    ...policy,
    bodyTimeoutMs: 10,
  });
  const req = new Request(origin + "/participant/respond", {
    method: "POST",
    headers: {
      origin,
      "x-csrf-token": csrf,
      "content-type": "application/json",
    },
    body,
    duplex: "half",
  } as RequestInit & { duplex: "half" });
  assert.equal((await handler(req)).status, 408);
  assert.equal(cancelled, true);
  const controller = new AbortController();
  controller.abort();
  let called = false;
  const abortHandler = createParticipantHandler(
    registry,
    {
      authenticate: async () => {
        called = true;
        return null;
      },
    },
    policy,
  );
  const aborted = new Request(request("/participant/session"), {
    signal: controller.signal,
  });
  assert.equal((await abortHandler(aborted)).status, 408);
  assert.equal(called, false);
  assert.equal(
    (await registry.reviewOffer(participant, "offer")).offer.status,
    "offered",
  );
});

test("HTTP uncertain commit returns sanitized failure and exact retry retrieves original receipt", async (t) => {
  const { registry, db, policy: registryPolicy } = await setup(t);
  const envelope = {
    commandId: "uncertain-http",
    input: await response(registry),
  };
  let transactions = 0;
  const uncertain: Database = {
    transaction: async (fn) => {
      const result = await db.transaction(fn);
      transactions++;
      if (transactions === 1)
        throw new Error("password private diagnostic lost response");
      return result;
    },
    close: async () => {},
  };
  const handler = createParticipantHandler(
    new PermissionRegistry(uncertain, registryPolicy),
    auth,
    policy,
  );
  const lost = await handler(request("/participant/respond", envelope));
  assert.equal(lost.status, 503);
  assert.deepEqual(await details(lost), { error: "operation_unavailable" });
  assert.equal(
    (await registry.reviewOffer(participant, "offer")).offer.status,
    "accepted",
  );
  const recovered = await handler(request("/participant/respond", envelope));
  assert.equal(recovered.status, 200);
  assert.equal((await details(recovered)).status, "accepted");
  await scoped(db, manager, async (tx) => {
    assert.equal((await tx.list("consent")).length, 1);
    assert.equal(
      (await tx.audits()).filter(
        (a) => a.type === "participant.offer.responded",
      ).length,
      1,
    );
  });
});

test("HTTP policy is captured, HTTPS only, and native same-origin read metadata is supported", async (t) => {
  const { registry } = await setup(t);
  for (const badOrigin of [
    "http://private.example",
    origin + "/",
    origin + "/path",
    "https://user:password@private.example",
  ])
    assert.throws(() =>
      createParticipantHandler(registry, auth, {
        ...policy,
        origin: badOrigin,
      }),
    );
  assert.throws(() =>
    createParticipantHandler(registry, auth, { ...policy, bodyTimeoutMs: 0 }),
  );
  const configuration = { ...policy };
  const handler = createParticipantHandler(registry, auth, configuration);
  configuration.origin = "https://foreign.example";
  assert.equal(
    (
      await handler(
        new Request(origin + "/participant/session", {
          headers: { "sec-fetch-site": "same-origin" },
        }),
      )
    ).status,
    200,
  );
  assert.equal(
    (await handler(new Request(origin + "/participant/session"))).status,
    403,
  );
});
