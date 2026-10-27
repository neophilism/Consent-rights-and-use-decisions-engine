import { timingSafeEqual } from "node:crypto";
import {
  DomainError,
  invariant,
  nonempty,
  requireScope,
  validTime,
} from "./contracts.ts";
import type { Context, Scope } from "./contracts.ts";
import { assertContext } from "./index.ts";
import type { PermissionRegistry } from "./registry.ts";

export type ParticipantSession = Readonly<{
  context: Context;
  csrfToken: string;
}>;
export type ParticipantAuthentication = Readonly<{
  authenticate(
    metadata: { url: string; method: string; headers: Headers },
    signal: AbortSignal,
  ): Promise<ParticipantSession | null>;
}>;
export type ParticipantHttpPolicy = Scope &
  Readonly<{
    origin: string;
    authenticationTimeoutMs?: number;
    bodyTimeoutMs?: number;
  }>;
const responseHeaders = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "private, no-store",
  pragma: "no-cache",
  vary: "Cookie, Authorization",
  "x-content-type-options": "nosniff",
  "cross-origin-resource-policy": "same-origin",
};
function reply(status: number, value: unknown): Response {
  const body = JSON.stringify(value);
  invariant(
    Buffer.byteLength(body) <= 262144,
    "response_too_large",
    "Response budget exceeded",
  );
  return new Response(body, { status, headers: responseHeaders });
}
function exact(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  invariant(
    value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Object.keys(value).length === keys.length &&
      keys.every((k) => Object.hasOwn(value, k)),
    "invalid_request",
    "Exact JSON fields required",
  );
  return value as Record<string, unknown>;
}
function revision(value: unknown): number {
  invariant(
    Number.isSafeInteger(value) && (value as number) > 0,
    "invalid_request",
    "Positive viewed revision required",
  );
  return value as number;
}
function text(value: unknown): string {
  nonempty(value, "Identifier", 200);
  return value;
}
const statusCodes: Readonly<Record<string, number>> = {
  authentication_required: 401,
  authentication_unavailable: 503,
  participant_required: 403,
  manager_required: 403,
  scope_denied: 403,
  origin_denied: 403,
  csrf_denied: 403,
  offer_unavailable: 404,
  consent_unavailable: 404,
  route_not_found: 404,
  method_denied: 405,
  revision_conflict: 409,
  review_changed: 409,
  offer_closed: 409,
  offer_expired: 409,
  already_withdrawn: 409,
  idempotency_conflict: 409,
  request_aborted: 408,
  body_timeout: 408,
  body_too_large: 413,
  response_too_large: 413,
  unsupported_media: 415,
  invalid_request: 400,
  invalid_input: 400,
  invalid_digest: 400,
  invalid_revision: 400,
  invalid_response: 400,
  acknowledgement_required: 400,
};
async function session(
  auth: ParticipantAuthentication,
  request: Request,
  timeoutMs: number,
): Promise<ParticipantSession> {
  const controller = new AbortController(),
    deadline = performance.now() + timeoutMs;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let interrupt = () => {};
  let timedOut = false;
  const abort = () => controller.abort();
  request.signal.addEventListener("abort", abort, { once: true });
  if (request.signal.aborted) abort();
  try {
    invariant(
      !controller.signal.aborted && performance.now() < deadline,
      "request_aborted",
      "Request cancelled",
    );
    const result = await Promise.race([
      Promise.resolve()
        .then(() => {
          invariant(
            !controller.signal.aborted && performance.now() < deadline,
            "request_aborted",
            "Request cancelled",
          );
          const metadata = {
            url: request.url,
            method: request.method,
            headers: new Headers(request.headers),
          };
          invariant(
            !controller.signal.aborted && performance.now() < deadline,
            "authentication_unavailable",
            "Authentication deadline exceeded",
          );
          return auth.authenticate(metadata, controller.signal);
        })
        .then((value) => {
          invariant(
            !controller.signal.aborted && performance.now() < deadline,
            "authentication_unavailable",
            "Authentication deadline exceeded",
          );
          const captured = value === null ? null : structuredClone(value);
          invariant(
            performance.now() < deadline,
            "authentication_unavailable",
            "Authentication deadline exceeded",
          );
          return captured;
        })
        .catch(() => {
          throw new DomainError(
            "authentication_unavailable",
            "Authentication unavailable",
          );
        }),
      new Promise<never>((_, reject) => {
        interrupt = () =>
          reject(
            new DomainError(
              timedOut ? "authentication_unavailable" : "request_aborted",
              "Authentication interrupted",
            ),
          );
        controller.signal.addEventListener("abort", interrupt, { once: true });
        timer = setTimeout(() => {
          timedOut = true;
          controller.abort();
        }, timeoutMs);
      }),
    ]);
    invariant(
      !controller.signal.aborted && performance.now() < deadline,
      timedOut ? "authentication_unavailable" : "request_aborted",
      "Request cancelled",
    );
    invariant(result, "authentication_required", "Authentication required");
    try {
      const c = result.context;
      assertContext(c);
      for (const field of [
        c.tenantId,
        c.projectId,
        c.actor.id,
        c.purpose,
        c.requestId,
      ])
        nonempty(field, "Authenticated context", 200);
      nonempty(c.now, "Authenticated time", 64);
      validTime(c.now);
      invariant(
        Array.isArray(c.actor.roles) &&
          c.actor.roles.length <= 128 &&
          c.actor.roles.every(
            (role) => typeof role === "string" && role.length <= 128,
          ),
        "authentication_unavailable",
        "Invalid roles",
      );
    } catch {
      throw new DomainError(
        "authentication_unavailable",
        "Invalid authenticated context",
      );
    }
    invariant(
      result.context.actor.kind === "human" &&
        result.context.actor.roles.includes("participant"),
      "participant_required",
      "Participant required",
    );
    invariant(
      typeof result.csrfToken === "string" &&
        /^[A-Za-z0-9_-]{32,256}$/.test(result.csrfToken),
      "authentication_unavailable",
      "Invalid session binding",
    );
    invariant(
      !controller.signal.aborted && performance.now() < deadline,
      "authentication_unavailable",
      "Authentication deadline exceeded",
    );
    return result;
  } finally {
    if (timer) clearTimeout(timer);
    request.signal.removeEventListener("abort", abort);
    controller.signal.removeEventListener("abort", interrupt);
    controller.abort();
  }
}
async function jsonBody(request: Request, timeoutMs: number): Promise<unknown> {
  invariant(
    /^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
      request.headers.get("content-type") ?? "",
    ) && [null, "identity"].includes(request.headers.get("content-encoding")),
    "unsupported_media",
    "Uncompressed JSON required",
  );
  const length = request.headers.get("content-length");
  invariant(
    length === null || (/^\d+$/.test(length) && Number(length) <= 16384),
    "body_too_large",
    "Request body exceeds budget",
  );
  invariant(request.body, "invalid_request", "Body required");
  const reader = request.body.getReader(),
    deadline = performance.now() + timeoutMs;
  function gate() {
    invariant(!request.signal.aborted, "request_aborted", "Request cancelled");
    invariant(
      performance.now() < deadline,
      "body_timeout",
      "Body deadline exceeded",
    );
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  let interrupt = () => {};
  const interrupted = new Promise<never>((_, reject) => {
    interrupt = () =>
      reject(new DomainError("request_aborted", "Request cancelled"));
    request.signal.addEventListener("abort", interrupt, { once: true });
    timer = setTimeout(
      () => reject(new DomainError("body_timeout", "Body deadline exceeded")),
      timeoutMs,
    );
  });
  try {
    invariant(!request.signal.aborted, "request_aborted", "Request cancelled");
    const chunks: Uint8Array[] = [];
    let bytes = 0,
      count = 0;
    while (true) {
      gate();
      const part = await Promise.race([reader.read(), interrupted]);
      gate();
      if (part.done) break;
      count++;
      bytes += part.value.byteLength;
      invariant(
        bytes <= 16384 && count <= 4096,
        "body_too_large",
        "Request body exceeds budget",
      );
      chunks.push(new Uint8Array(part.value));
    }
    let parsed: unknown;
    gate();
    try {
      parsed = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)),
      );
    } catch {
      throw new DomainError("invalid_request", "UTF8 JSON required");
    }
    gate();
    return parsed;
  } finally {
    if (timer) clearTimeout(timer);
    request.signal.removeEventListener("abort", interrupt);
    // A hostile stream cancellation callback must not hold the handler open.
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

/** Private host adapter. The authentication callback, clock, mappings and DB remain trusted. */
export function createParticipantHandler(
  registry: PermissionRegistry,
  auth: ParticipantAuthentication,
  configuration: ParticipantHttpPolicy,
): (request: Request) => Promise<Response> {
  const policy = structuredClone(configuration);
  nonempty(policy.tenantId, "Tenant id", 200);
  nonempty(policy.projectId, "Project id", 200);
  const origin = new URL(policy.origin);
  invariant(
    origin.protocol === "https:" &&
      origin.origin === policy.origin &&
      !origin.username &&
      !origin.password,
    "invalid_policy",
    "An exact HTTPS origin is required",
  );
  const authTimeout = policy.authenticationTimeoutMs ?? 5000,
    bodyTimeout = policy.bodyTimeoutMs ?? 5000;
  for (const value of [authTimeout, bodyTimeout])
    invariant(
      Number.isSafeInteger(value) && value >= 10 && value <= 30000,
      "invalid_policy",
      "Timeout must be between 10 and 30000 ms",
    );
  return async (request) => {
    try {
      const url = new URL(request.url);
      invariant(
        url.origin === policy.origin && !url.username && !url.password,
        "origin_denied",
        "Origin denied",
      );
      const known = [
        "/participant/session",
        "/participant/offer",
        "/participant/respond",
        "/participant/withdraw",
      ];
      invariant(
        known.includes(url.pathname),
        "route_not_found",
        "Unknown route",
      );
      const read =
        url.pathname === "/participant/session" ||
        url.pathname === "/participant/offer";
      invariant(
        request.method === (read ? "GET" : "POST"),
        "method_denied",
        "Unsupported method",
      );
      const suppliedOrigin = request.headers.get("origin"),
        site = request.headers.get("sec-fetch-site");
      invariant(
        (suppliedOrigin === null || suppliedOrigin === policy.origin) &&
          (site === null || site === "same-origin") &&
          (read
            ? suppliedOrigin === policy.origin || site === "same-origin"
            : suppliedOrigin === policy.origin),
        "origin_denied",
        "Same-origin request required",
      );
      if (url.pathname === "/participant/offer")
        invariant(
          [...url.searchParams.keys()].length === 1 &&
            url.searchParams.has("offerId"),
          "invalid_request",
          "Exact offer query required",
        );
      else
        invariant(
          url.search === "",
          "invalid_request",
          "Query is not supported",
        );
      const identity = await session(auth, request, authTimeout);
      requireScope(identity.context, policy);
      if (url.pathname === "/participant/session")
        return reply(200, {
          csrfToken: identity.csrfToken,
          actorId: identity.context.actor.id,
          tenantId: policy.tenantId,
          projectId: policy.projectId,
        });
      if (url.pathname === "/participant/offer")
        return reply(
          200,
          await registry.reviewOffer(
            identity.context,
            text(url.searchParams.get("offerId")),
          ),
        );
      const supplied = request.headers.get("x-csrf-token") ?? "";
      invariant(
        /^[A-Za-z0-9_-]{32,256}$/.test(supplied) &&
          supplied.length === identity.csrfToken.length &&
          timingSafeEqual(
            Buffer.from(supplied),
            Buffer.from(identity.csrfToken),
          ),
        "csrf_denied",
        "Session CSRF binding required",
      );
      const parsed = await jsonBody(request, bodyTimeout);
      invariant(
        !request.signal.aborted,
        "request_aborted",
        "Request cancelled",
      );
      if (url.pathname === "/participant/respond") {
        const envelope = exact(parsed, ["commandId", "input"]);
        const input = exact(envelope.input, [
          "offerId",
          "expectedRevision",
          "reviewDigest",
          "response",
          "acknowledged",
        ]);
        return reply(
          200,
          await registry.respondToOffer(
            identity.context,
            {
              offerId: text(input.offerId),
              expectedRevision: revision(input.expectedRevision),
              reviewDigest: text(input.reviewDigest),
              response: input.response as "accept" | "decline",
              acknowledged: input.acknowledged as boolean,
            },
            text(envelope.commandId),
          ),
        );
      }
      const envelope = exact(parsed, [
        "commandId",
        "offerId",
        "expectedConsentRevision",
      ]);
      const review = await registry.reviewOffer(
        identity.context,
        text(envelope.offerId),
      );
      invariant(
        review.consent && review.offer.consent,
        "consent_unavailable",
        "Captured consent unavailable",
      );
      invariant(
        !request.signal.aborted,
        "request_aborted",
        "Request cancelled",
      );
      return reply(
        200,
        await registry.withdraw(
          identity.context,
          "consent",
          review.consent.ref.id,
          revision(envelope.expectedConsentRevision),
          text(envelope.commandId),
        ),
      );
    } catch (error) {
      const code =
        error !== null &&
        typeof error === "object" &&
        "code" in error &&
        typeof error.code === "string"
          ? error.code
          : "";
      return reply(
        Object.hasOwn(statusCodes, code) ? statusCodes[code]! : 503,
        {
          error: Object.hasOwn(statusCodes, code)
            ? code
            : "operation_unavailable",
        },
      );
    }
  };
}
