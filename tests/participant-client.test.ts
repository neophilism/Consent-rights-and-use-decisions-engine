import test from "node:test";
import assert from "node:assert/strict";
import { scoped } from "@accountability/evidence/database";
import type { Database } from "@accountability/evidence/database";
import {
  ParticipantClient,
  ParticipantClientError,
} from "../src/participant-client.ts";
import { createParticipantHandler } from "../src/participant-http.ts";
import { PermissionRegistry } from "../src/registry.ts";
import { canonical, digest } from "../src/contracts.ts";
import { setup, participant, manager, input } from "./participant-fixture.ts";

const origin = "https://private.example";
const scope = { tenantId: manager.tenantId, projectId: manager.projectId };
const csrf = "s".repeat(40);
const policy = { ...scope, origin };
const jsonHeaders = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "private, no-store",
};
const json = (v: unknown, status = 200) =>
  new Response(JSON.stringify(v), { status, headers: jsonHeaders });
const session = (actorId = participant.actor.id, token = csrf) =>
  json({ ...scope, actorId, csrfToken: token });
const isCode = (code: string) => (e: unknown) =>
  e instanceof ParticipantClientError && e.code === code && e.message === code;
type Recorded = {
  path: string;
  body: string | undefined;
  csrf: string | null;
  signal: AbortSignal | undefined;
};
function transport(
  handler: (r: Request) => Promise<Response>,
  requests: Recorded[] = [],
): typeof fetch {
  return async (url, init) => {
    const req = new Request(String(url), {
      ...init,
      headers: {
        ...Object.fromEntries(new Headers(init?.headers)),
        origin,
        "sec-fetch-site": "same-origin",
      },
    });
    requests.push({
      path: new URL(req.url).pathname,
      body: typeof init?.body === "string" ? init.body : undefined,
      csrf: req.headers.get("x-csrf-token"),
      signal: init?.signal ?? undefined,
    });
    assert.equal(init?.credentials, "same-origin");
    assert.equal(init?.redirect, "error");
    assert.equal(init?.cache, "no-store");
    return handler(req);
  };
}
function handler(
  registry: PermissionRegistry,
  identity = () => participant,
  token = () => csrf,
) {
  return createParticipantHandler(
    registry,
    { authenticate: async () => ({ context: identity(), csrfToken: token() }) },
    policy,
  );
}
async function syntheticReview() {
  const offer = {
    ...input,
    ref: { ...scope, kind: "consent-offer", id: input.id, revision: 1 },
    createdAt: manager.now,
    createdBy: manager.actor.id,
    status: "offered",
    resolvedAt: null,
    resolvedBy: null,
    consent: null,
  };
  return {
    offer,
    reviewDigest: digest({ profile: "participant-consent-offer-v1", offer }),
    responseOpen: true,
    consent: null,
    warnings: ["Fictional unverified test review"],
  };
}

test("client reviews exact actual offer, captures affirmative response and withdraws current consent", async (t) => {
  const { registry, db } = await setup(t);
  const requests: Recorded[] = [];
  const client = new ParticipantClient(
    origin,
    scope,
    transport(handler(registry), requests),
  );
  await assert.rejects(
    client.respond("before-review", { response: "accept", acknowledged: true }),
    isCode("review_required"),
  );
  const reviewed = await client.review("offer");
  assert.deepEqual(reviewed, await registry.reviewOffer(participant, "offer"));
  // Returned values cannot change the viewed terms, IDs or digest used in the request.
  (reviewed.offer as { disclosure: string }).disclosure =
    "<script>ignored local mutation</script>";
  (reviewed as { reviewDigest: string }).reviewDigest = "f".repeat(64);
  await assert.rejects(
    client.respond("no-ack", { response: "accept", acknowledged: false }),
    isCode("invalid_request"),
  );
  const result = await client.respond("explicit-accept", {
    response: "accept",
    acknowledged: true,
  });
  assert.equal(result.operation, "respond");
  assert.equal(
    result.operation === "respond" && result.offer.status,
    "accepted",
  );
  assert.equal(client.pending, null);
  await assert.rejects(
    client.withdraw("unreviewed"),
    isCode("review_required"),
  );
  const current = await client.review("offer");
  assert.equal(current.consent?.withdrawnAt, null);
  const withdrawn = await client.withdraw("explicit-withdraw");
  assert.equal(
    withdrawn.operation === "withdraw" && withdrawn.consent.ref.revision,
    2,
  );
  assert.equal(
    withdrawn.operation === "withdraw" && withdrawn.consent.withdrawnAt,
    participant.now,
  );
  assert.equal(
    (await client.review("offer")).consent?.withdrawnAt,
    participant.now,
  );
  await assert.rejects(client.withdraw("again"), isCode("review_required"));
  await scoped(db, manager, async (tx) => {
    assert.equal((await tx.list("consent")).length, 1);
    assert.equal(
      (await tx.audits()).filter(
        (x) => x.type === "participant.offer.responded",
      ).length,
      1,
    );
  });
  assert.ok(requests.every((x) => x.signal?.aborted));
  assert.equal(requests.filter((x) => x.body !== undefined).length, 2);
});

test("actual lost COMMIT acknowledgement locks immutable response and explicit replay gets fresh CSRF without reviving withdrawal", async (t) => {
  const { registry, db, policy: registryPolicy } = await setup(t);
  let lose = true,
    token = csrf;
  const uncertain: Database = {
    transaction: async (fn) => {
      const value = await db.transaction(fn);
      // Lose acknowledgement only for the actual accepting transaction.
      if (lose && (value as { status?: string })?.status === "accepted") {
        lose = false;
        throw new Error("private diagnostic");
      }
      return value;
    },
    close: async () => {},
  };
  const requests: Recorded[] = [];
  const client = new ParticipantClient(
    origin,
    scope,
    transport(
      handler(
        new PermissionRegistry(uncertain, registryPolicy),
        () => participant,
        () => token,
      ),
      requests,
    ),
  );
  await client.review("offer");
  await assert.rejects(
    client.respond("stable-command", {
      response: "accept",
      acknowledged: true,
    }),
    isCode("outcome_unknown"),
  );
  const retained = client.pending!;
  assert.equal(retained.operation, "respond");
  assert.equal(
    (await registry.reviewOffer(participant, "offer")).offer.status,
    "accepted",
  );
  if (retained.operation === "respond")
    (retained.command.input as { response: string }).response = "decline";
  await assert.rejects(client.review("offer"), isCode("client_locked"));
  await assert.rejects(
    client.respond("new-command", { response: "decline", acknowledged: false }),
    isCode("client_locked"),
  );
  const accepted = await registry.reviewOffer(participant, "offer");
  await registry.withdraw(
    participant,
    "consent",
    accepted.consent!.ref.id,
    1,
    "external-withdraw",
  );
  token = "n".repeat(40);
  const replay = await client.resolvePending();
  assert.equal(
    replay.operation === "respond" && replay.offer.status,
    "accepted",
  );
  const writes = requests.filter((x) => x.body !== undefined);
  assert.equal(writes.length, 2);
  assert.equal(writes[0]!.body, writes[1]!.body);
  assert.equal(writes[1]!.csrf, token);
  assert.equal(
    (await client.review("offer")).consent?.withdrawnAt,
    participant.now,
  );
  assert.equal(client.pending, null);
});

test("actual decline has no consent; cancellation after viewed review retains exact rejected command", async (t) => {
  const { registry, db } = await setup(t);
  const first = new ParticipantClient(
    origin,
    scope,
    transport(handler(registry)),
  );
  await first.review("offer");
  const declined = await first.respond("decline", {
    response: "decline",
    acknowledged: false,
  });
  assert.equal(
    declined.operation === "respond" && declined.offer.status,
    "declined",
  );
  await scoped(db, manager, async (tx) =>
    assert.equal((await tx.list("consent")).length, 0),
  );
  await registry.createOffer(
    manager,
    { ...input, id: "cancelled" },
    "create-cancelled",
  );
  const client = new ParticipantClient(
    origin,
    scope,
    transport(handler(registry)),
  );
  await client.review("cancelled");
  await registry.cancelOffer(manager, "cancelled", 1, "cancel");
  await assert.rejects(
    client.respond("stale-accept", { response: "accept", acknowledged: true }),
    isCode("request_rejected"),
  );
  assert.equal(client.pending?.operation, "respond");
  await assert.rejects(client.resolvePending(), isCode("request_rejected"));
  assert.equal(
    (await registry.reviewOffer(participant, "cancelled")).offer.status,
    "cancelled",
  );
});

test("actual uncertain withdrawal replays exactly and current mapping denial cannot clear pending", async (t) => {
  const { registry, db, policy: registryPolicy } = await setup(t);
  let lose = true,
    revoked = false;
  const requests: Recorded[] = [];
  const h = handler(registry);
  const send: typeof fetch = transport(async (req) => {
    if (revoked)
      return handler(
        new PermissionRegistry(db, {
          ...registryPolicy,
          participantActors: {},
        }),
      )(req);
    const result = await h(req);
    if (new URL(req.url).pathname === "/participant/withdraw" && lose) {
      lose = false;
      throw new Error("lost result");
    }
    return result;
  }, requests);
  const client = new ParticipantClient(origin, scope, send);
  await client.review("offer");
  await client.respond("accept", { response: "accept", acknowledged: true });
  await client.review("offer");
  await assert.rejects(client.withdraw("withdraw"), isCode("outcome_unknown"));
  const original = client.pending;
  revoked = true;
  await assert.rejects(client.resolvePending(), isCode("request_rejected"));
  assert.deepEqual(client.pending, original);
  revoked = false;
  const replay = await client.resolvePending();
  assert.equal(
    replay.operation === "withdraw" && replay.consent.ref.revision,
    2,
  );
  const writes = requests.filter((x) => x.path === "/participant/withdraw");
  assert.equal(writes.length, 3);
  assert.ok(writes.every((x) => x.body === writes[0]!.body));
});

test("client rejects tampered reviews, exact-field/scope/digest/capture inconsistencies before any command", async () => {
  const original = await syntheticReview();
  for (const mutate of [
    (r: any) => {
      r.offer.terms.resource.ref.projectId = "foreign";
    },
    (r: any) => {
      r.offer.disclosure += "changed";
    },
    (r: any) => {
      r.offer.ref.id = "other";
    },
    (r: any) => {
      r.extra = "credential";
    },
    (r: any) => {
      r.offer.status = "accepted";
    },
    (r: any) => {
      r.offer.terms.actions = ["*"];
    },
    (r: any) => {
      r.offer.terms.evidence.revision = 0;
    },
    (r: any) => {
      r.offer.terms.audiences = [];
    },
  ]) {
    const changed = structuredClone(original);
    mutate(changed);
    let writes = 0;
    const client = new ParticipantClient(origin, scope, async (url, init) => {
      if (init?.method === "POST") writes++;
      return String(url).endsWith("/session") ? session() : json(changed);
    });
    await assert.rejects(client.review("offer"), isCode("invalid_response"));
    await assert.rejects(
      client.respond("never", { response: "accept", acknowledged: true }),
      isCode("review_required"),
    );
    assert.equal(writes, 0);
  }
});

test("malformed success retains pending, forged terminal fields cannot acknowledge a different action or edition", async (t) => {
  const { registry } = await setup(t);
  const h = handler(registry);
  let malformed = true;
  const client = new ParticipantClient(
    origin,
    scope,
    transport(async (req) => {
      const r = await h(req);
      if (new URL(req.url).pathname === "/participant/respond" && malformed) {
        const changed = (await r.json()) as Record<string, any>;
        changed.terms.audiences = ["changed"];
        return json(changed);
      }
      return r;
    }),
  );
  await client.review("offer");
  await assert.rejects(
    client.respond("accept", { response: "accept", acknowledged: true }),
    isCode("invalid_response"),
  );
  assert.ok(client.pending);
  malformed = false;
  await client.resolvePending();
  assert.equal(client.pending, null);
  assert.equal(
    (await registry.reviewOffer(participant, "offer")).offer.status,
    "accepted",
  );
});

test("identity change permanently closes replay; disposal fences late responses and preserves pending metadata", async () => {
  const review = await syntheticReview();
  let actor = participant.actor.id,
    writes = 0;
  const client = new ParticipantClient(origin, scope, async (url, init) => {
    if (String(url).endsWith("/session")) return session(actor);
    if (init?.method === "POST") {
      writes++;
      throw new Error("lost");
    }
    return json(review);
  });
  await client.review("offer");
  await assert.rejects(
    client.respond("accept", { response: "accept", acknowledged: true }),
    isCode("outcome_unknown"),
  );
  actor = "other-person";
  await assert.rejects(client.resolvePending(), isCode("identity_changed"));
  assert.equal(client.closed, true);
  assert.ok(client.pending);
  assert.equal(writes, 1);
  await assert.rejects(client.resolvePending(), isCode("client_locked"));

  let finish!: (r: Response) => void, ready!: () => void;
  const started = new Promise<void>((r) => {
    ready = r;
  });
  const delayed = new ParticipantClient(origin, scope, async (url, init) => {
    if (String(url).endsWith("/session")) return session();
    if (init?.method !== "POST") return json(review);
    ready();
    return new Promise((r) => {
      finish = r;
    });
  });
  await delayed.review("offer");
  const command = delayed.respond("explicit", {
    response: "decline",
    acknowledged: false,
  });
  await started;
  delayed.dispose();
  await assert.rejects(command, isCode("outcome_unknown"));
  finish(json({ secret: "late" }));
  await new Promise((r) => setImmediate(r));
  assert.ok(delayed.pending);
  assert.equal(delayed.closed, true);
});

function block(ms: number) {
  const until = performance.now() + ms;
  while (performance.now() < until) {}
}
test("transport/body monotonic deadlines, limits and cancellation sanitize failures and close every signal", async () => {
  const review = await syntheticReview();
  for (const scenario of [
    "blocked",
    "hung",
    "oversize",
    "chunks",
    "encoding",
    "redirect",
    "cache",
    "stream-block",
    "hostile-error",
  ]) {
    const signals: AbortSignal[] = [];
    let cancelled = false;
    const client = new ParticipantClient(
      origin,
      scope,
      async (_url, init) => {
        signals.push(init!.signal!);
        if (scenario === "blocked") {
          block(40);
          return session();
        }
        if (scenario === "hung") return new Promise(() => {});
        if (scenario === "hostile-error")
          throw new ParticipantClientError("private credential diagnostic");
        if (scenario === "redirect")
          return Response.redirect(origin + "/foreign");
        if (scenario === "cache")
          return new Response("{}", {
            headers: { "content-type": "application/json" },
          });
        if (scenario === "oversize") return json({ value: "x".repeat(262145) });
        let count = 0;
        const stream = new ReadableStream<Uint8Array>(
          {
            pull(c) {
              if (scenario === "stream-block") block(40);
              if (scenario === "encoding") {
                c.enqueue(new Uint8Array([255]));
                c.close();
              } else {
                count++;
                c.enqueue(new Uint8Array());
                if (count > 4100) c.close();
              }
            },
            cancel() {
              cancelled = true;
              return new Promise(() => {});
            },
          },
          { highWaterMark: 0 },
        );
        return new Response(stream, { headers: jsonHeaders });
      },
      10,
    );
    await assert.rejects(
      client.review("offer"),
      (e) =>
        e instanceof ParticipantClientError &&
        [
          "outcome_unknown",
          "invalid_response",
          "response_limit",
          "session_unavailable",
        ].includes(e.code),
      scenario,
    );
    assert.ok(
      signals.every((s) => s.aborted),
      scenario,
    );
    if (["chunks", "stream-block"].includes(scenario))
      assert.equal(cancelled, true, scenario);
    assert.equal(client.pending, null);
  }
  // A post-stage timeout retains the exact command rather than granting a new response.
  const client = new ParticipantClient(
    origin,
    scope,
    async (url, init) => {
      if (String(url).endsWith("/session")) return session();
      if (init?.method !== "POST") return json(review);
      block(40);
      return json({});
    },
    10,
  );
  await client.review("offer");
  await assert.rejects(
    client.respond("stable", { response: "decline", acknowledged: false }),
    isCode("outcome_unknown"),
  );
  assert.ok(client.pending);
});

test("configuration, explicit decision, busy gates and captured configuration reject unsafe admission", async () => {
  for (const bad of [
    "http://private.example",
    origin + "/",
    origin + "/path",
    "https://a:b@private.example",
  ])
    assert.throws(
      () => new ParticipantClient(bad, scope, fetch),
      isCode("invalid_configuration"),
    );
  for (const time of [0, 9, 30001, Infinity])
    assert.throws(() => new ParticipantClient(origin, scope, fetch, time));
  const configured = { ...scope },
    review = await syntheticReview();
  const client = new ParticipantClient(origin, configured, async (url) =>
    String(url).endsWith("/session") ? session() : json(review),
  );
  configured.projectId = "foreign";
  const pending = client.review("offer");
  await assert.rejects(client.review("offer"), isCode("client_locked"));
  await pending;
  for (const bad of [
    { response: "accept", acknowledged: true, extra: true },
    { response: "accept", acknowledged: "true" },
    { response: "", acknowledged: false },
  ])
    await assert.rejects(
      client.respond("bad", bad as any),
      (e) => e instanceof ParticipantClientError,
    );
  assert.equal(client.pending, null);
  assert.equal(canonical(review.offer.terms), canonical(input.terms));
});

test("profile hashing stays within exchange cancellation/deadline; late validation cannot unlock pending", async () => {
  const review = await syntheticReview();
  const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
  let slow = false,
    finish: (() => void) | undefined;
  crypto.subtle.digest = async (...args) => {
    if (slow)
      await new Promise<void>((resolve) => {
        finish = resolve;
      });
    return originalDigest(...args);
  };
  try {
    const declined = {
      ...review.offer,
      ref: { ...review.offer.ref, revision: 2 },
      status: "declined",
      resolvedAt: participant.now,
      resolvedBy: participant.actor.id,
    };
    const client = new ParticipantClient(
      origin,
      scope,
      async (url, init) =>
        String(url).endsWith("/session")
          ? session()
          : init?.method === "POST"
            ? json(declined)
            : json(review),
      100,
    );
    slow = true;
    await assert.rejects(client.review("offer"), isCode("outcome_unknown"));
    assert.equal(client.pending, null);
    finish!();
    await new Promise((r) => setImmediate(r));
    slow = false;
    await assert.rejects(
      client.respond("unviewed", { response: "accept", acknowledged: true }),
      isCode("review_required"),
    );
    await client.review("offer");
    // Acceptance verification hashes deterministic consent and the captured consent content.
    const consentRef = {
      ...scope,
      kind: "consent",
      id: digest({ profile: "offer-consent-v1", offer: review.offer.ref }),
      revision: 1,
    };
    const consent = {
      ...review.offer.terms,
      ref: consentRef,
      subjectId: review.offer.subjectId,
      withdrawnAt: null,
      recordedBy: participant.actor.id,
    };
    const accepted = {
      ...declined,
      status: "accepted",
      consent: { ref: consentRef, digest: digest(consent) },
    };
    const validating = new ParticipantClient(
      origin,
      scope,
      async (url, init) =>
        String(url).endsWith("/session")
          ? session()
          : init?.method === "POST"
            ? json(accepted)
            : json(review),
      100,
    );
    await validating.review("offer");
    slow = true;
    await assert.rejects(
      validating.respond("stable", { response: "accept", acknowledged: true }),
      isCode("outcome_unknown"),
    );
    const retained = validating.pending;
    finish!();
    slow = false;
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(validating.pending, retained);
    assert.ok(retained);
  } finally {
    crypto.subtle.digest = originalDigest;
  }
});
