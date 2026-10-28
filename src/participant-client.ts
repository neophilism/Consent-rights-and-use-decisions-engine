import type { Scope } from "./contracts.ts";
import type { Consent } from "./index.ts";
import type { ConsentOffer, ParticipantReview } from "./participant.ts";
import {
  ParticipantClientError,
  requireWire,
  identifier,
  exact,
  canonical,
  checkedReview,
  checkedOffer,
  checkedConsent,
} from "./participant-wire.ts";
export { ParticipantClientError } from "./participant-wire.ts";

export type ParticipantPending =
  | Readonly<{
      operation: "respond";
      command: Readonly<{
        commandId: string;
        input: Readonly<{
          offerId: string;
          expectedRevision: number;
          reviewDigest: string;
          response: "accept" | "decline";
          acknowledged: boolean;
        }>;
      }>;
    }>
  | Readonly<{
      operation: "withdraw";
      command: Readonly<{
        commandId: string;
        offerId: string;
        expectedConsentRevision: number;
      }>;
    }>;
export type ParticipantResult =
  | Readonly<{ operation: "respond"; offer: ConsentOffer }>
  | Readonly<{ operation: "withdraw"; consent: Consent }>;
function fail(code: string): never {
  throw new ParticipantClientError(code);
}

/** Explicit private participant requests; no automatic writes or background retries. */
export class ParticipantClient {
  readonly #origin: string;
  readonly #scope: Scope;
  readonly #fetch: typeof fetch;
  readonly #timeout: number;
  #actor: string | null = null;
  #review: ParticipantReview | null = null;
  #pending: ParticipantPending | null = null;
  #pendingReview: ParticipantReview | null = null;
  #busy = false;
  #closed = false;
  #controller: AbortController | null = null;
  constructor(
    origin: string,
    scope: Scope,
    transport: typeof fetch,
    timeoutMs = 15000,
  ) {
    let url: URL;
    try {
      url = new URL(origin);
    } catch {
      fail("invalid_configuration");
    }
    requireWire(
      url.protocol === "https:" &&
        url.origin === origin &&
        !url.username &&
        !url.password &&
        identifier(scope.tenantId) &&
        identifier(scope.projectId) &&
        typeof transport === "function" &&
        Number.isSafeInteger(timeoutMs) &&
        timeoutMs >= 10 &&
        timeoutMs <= 30000,
      "invalid_configuration",
    );
    this.#origin = origin;
    this.#scope = { tenantId: scope.tenantId, projectId: scope.projectId };
    this.#fetch = transport;
    this.#timeout = timeoutMs;
  }
  get origin(): string {
    return this.#origin;
  }
  get pending(): ParticipantPending | null {
    return structuredClone(this.#pending);
  }
  get closed(): boolean {
    return this.#closed;
  }
  dispose(): void {
    this.#closed = true;
    this.#actor = null;
    this.#review = null;
    this.#controller?.abort();
  }
  #available(pending = false): void {
    requireWire(
      !this.#closed &&
        !this.#busy &&
        (pending ? !!this.#pending : !this.#pending),
      "client_locked",
    );
  }
  async #exchange<T>(
    path: string,
    validate: (value: unknown, status: number) => T | Promise<T>,
    payload?: string,
    csrf?: string,
  ): Promise<T> {
    const controller = new AbortController(),
      deadline = performance.now() + this.#timeout;
    this.#controller = controller;
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let finished = false;
    const gate = () => {
      if (
        finished ||
        this.#closed ||
        controller.signal.aborted ||
        performance.now() >= deadline
      )
        fail("outcome_unknown");
    };
    let timer: ReturnType<typeof setTimeout> | undefined;
    let interrupt = () => {};
    const interrupted = new Promise<never>((_, reject) => {
      interrupt = () => reject(new ParticipantClientError("outcome_unknown"));
      controller.signal.addEventListener("abort", interrupt, { once: true });
      timer = setTimeout(() => controller.abort(), this.#timeout);
    });
    const operation = async () => {
      gate();
      const response = await this.#fetch(this.#origin + path, {
        method: payload === undefined ? "GET" : "POST",
        credentials: "same-origin",
        redirect: "error",
        cache: "no-store",
        signal: controller.signal,
        headers: {
          accept: "application/json",
          ...(payload === undefined
            ? {}
            : { "content-type": "application/json", "x-csrf-token": csrf! }),
        },
        ...(payload === undefined ? {} : { body: payload }),
      });
      try {
        gate();
      } catch (e) {
        void response.body?.cancel().catch(() => {});
        throw e;
      }
      if (
        response.redirected ||
        (response.url && response.url !== this.#origin + path) ||
        !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
          response.headers.get("content-type") ?? "",
        ) ||
        !/\bno-store\b/i.test(response.headers.get("cache-control") ?? "") ||
        ![null, "identity"].includes(
          response.headers.get("content-encoding"),
        ) ||
        !response.body
      ) {
        void response.body?.cancel().catch(() => {});
        fail("invalid_response");
      }
      reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0,
        count = 0;
      for (;;) {
        gate();
        const part = await reader.read();
        gate();
        if (part.done) break;
        requireWire(part.value instanceof Uint8Array);
        size += part.value.byteLength;
        if (size > 262144 || ++count > 4096) fail("response_limit");
        chunks.push(new Uint8Array(part.value));
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
      }
      gate();
      let value: unknown;
      try {
        value = JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(bytes),
        );
      } catch {
        fail("invalid_response");
      }
      gate();
      const result = await validate(value, response.status);
      gate();
      return result;
    };
    try {
      return await Promise.race([operation(), interrupted]);
    } catch (e) {
      throw e instanceof ParticipantClientError &&
        [
          "outcome_unknown",
          "invalid_response",
          "response_limit",
          "session_unavailable",
          "review_unavailable",
          "request_rejected",
        ].includes(e.code)
        ? new ParticipantClientError(e.code)
        : new ParticipantClientError("outcome_unknown");
    } finally {
      finished = true;
      if (timer) clearTimeout(timer);
      controller.signal.removeEventListener("abort", interrupt);
      controller.abort();
      if (reader) void reader.cancel().catch(() => {});
      if (this.#controller === controller) this.#controller = null;
    }
  }
  async #session(): Promise<string> {
    const s = await this.#exchange("/participant/session", (value, status) => {
      requireWire(status === 200, "session_unavailable");
      const s = exact(value, ["csrfToken", "actorId", "tenantId", "projectId"]);
      requireWire(
        identifier(s.actorId) &&
          s.tenantId === this.#scope.tenantId &&
          s.projectId === this.#scope.projectId &&
          typeof s.csrfToken === "string" &&
          /^[A-Za-z0-9_-]{32,256}$/.test(s.csrfToken),
      );
      return { actorId: s.actorId, csrfToken: s.csrfToken };
    });
    requireWire(!this.#closed, "client_closed");
    if (this.#actor !== null && this.#actor !== s.actorId) {
      this.dispose();
      fail("identity_changed");
    }
    this.#actor = s.actorId;
    return s.csrfToken;
  }
  async review(offerId: string): Promise<ParticipantReview> {
    this.#available();
    requireWire(identifier(offerId), "invalid_request");
    this.#busy = true;
    this.#review = null;
    try {
      await this.#session();
      const review = await this.#exchange(
        "/participant/offer?offerId=" + encodeURIComponent(offerId),
        (value, status) => {
          requireWire(status === 200, "review_unavailable");
          return checkedReview(this.#scope, offerId, value);
        },
      );
      requireWire(!this.#closed, "client_closed");
      this.#review = structuredClone(review);
      return structuredClone(review);
    } finally {
      this.#busy = false;
    }
  }
  async #run(
    pending: ParticipantPending,
    viewed: ParticipantReview,
  ): Promise<ParticipantResult> {
    const csrf = await this.#session();
    requireWire(!this.#closed, "client_closed");
    // Install immutable replay state BEFORE transport can see a mutation.
    this.#pending = structuredClone(pending);
    this.#pendingReview = structuredClone(viewed);
    const result = await this.#exchange<ParticipantResult>(
      "/participant/" + pending.operation,
      async (value, httpStatus) => {
        requireWire(
          httpStatus === 200,
          httpStatus >= 400 && httpStatus < 500
            ? "request_rejected"
            : "outcome_unknown",
        );
        let result: ParticipantResult;
        if (pending.operation === "respond") {
          const offer = await checkedOffer(this.#scope, value),
            before = viewed.offer;
          const { ref, status, resolvedAt, resolvedBy, consent, ...unchanged } =
            offer;
          const {
            ref: oldRef,
            status: oldStatus,
            resolvedAt: oldAt,
            resolvedBy: oldBy,
            consent: oldConsent,
            ...original
          } = before;
          requireWire(
            canonical(unchanged) === canonical(original) &&
              ref.revision === before.ref.revision + 1 &&
              ref.id === before.ref.id &&
              resolvedBy === this.#actor &&
              status ===
                (pending.command.input.response === "accept"
                  ? "accepted"
                  : "declined"),
          );
          result = { operation: "respond", offer };
        } else {
          const consent = checkedConsent(this.#scope, value),
            before = viewed.consent!;
          requireWire(
            consent.ref.revision === before.ref.revision + 1 &&
              consent.withdrawnAt !== null &&
              canonical({ ...consent, ref: before.ref, withdrawnAt: null }) ===
                canonical(before),
          );
          result = { operation: "withdraw", consent };
        }
        return result;
      },
      JSON.stringify(pending.command),
      csrf,
    );
    requireWire(!this.#closed, "client_closed");
    this.#pending = null;
    this.#pendingReview = null;
    this.#review = null;
    return structuredClone(result);
  }
  async respond(
    commandId: string,
    decision: Readonly<{
      response: "accept" | "decline";
      acknowledged: boolean;
    }>,
  ): Promise<ParticipantResult> {
    this.#available();
    requireWire(identifier(commandId), "invalid_request");
    const d = exact(decision, ["response", "acknowledged"]);
    requireWire(
      ["accept", "decline"].includes(d.response as string) &&
        typeof d.acknowledged === "boolean" &&
        (d.response !== "accept" || d.acknowledged),
      "invalid_request",
    );
    requireWire(
      this.#review?.responseOpen && this.#review.offer.status === "offered",
      "review_required",
    );
    const viewed = structuredClone(this.#review);
    const pending: ParticipantPending = {
      operation: "respond",
      command: {
        commandId,
        input: {
          offerId: viewed.offer.id,
          expectedRevision: viewed.offer.ref.revision,
          reviewDigest: viewed.reviewDigest,
          response: d.response as "accept" | "decline",
          acknowledged: d.acknowledged,
        },
      },
    };
    this.#busy = true;
    try {
      return await this.#run(pending, viewed);
    } finally {
      this.#busy = false;
    }
  }
  async withdraw(commandId: string): Promise<ParticipantResult> {
    this.#available();
    requireWire(identifier(commandId), "invalid_request");
    requireWire(
      this.#review?.offer.status === "accepted" &&
        this.#review.consent?.withdrawnAt === null,
      "review_required",
    );
    const viewed = structuredClone(this.#review);
    const pending: ParticipantPending = {
      operation: "withdraw",
      command: {
        commandId,
        offerId: viewed.offer.id,
        expectedConsentRevision: viewed.consent!.ref.revision,
      },
    };
    this.#busy = true;
    try {
      return await this.#run(pending, viewed);
    } finally {
      this.#busy = false;
    }
  }
  async resolvePending(): Promise<ParticipantResult> {
    this.#available(true);
    const pending = structuredClone(this.#pending!),
      viewed = structuredClone(this.#pendingReview!);
    this.#busy = true;
    try {
      return await this.#run(pending, viewed);
    } finally {
      this.#busy = false;
    }
  }
}
