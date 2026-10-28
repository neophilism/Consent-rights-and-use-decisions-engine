// Browser-compatible validation for the accepted participant JSON profile.
// Digests check internal consistency; authenticated transport remains the trust boundary.
import type { Scope, Ref } from "./contracts.ts";
import type { Consent, PermissionTerms } from "./index.ts";
import type { ConsentOffer, ParticipantReview } from "./participant.ts";

export class ParticipantClientError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "ParticipantClientError";
    this.code = code;
  }
}
export function requireWire(
  ok: unknown,
  code = "invalid_response",
): asserts ok {
  if (!ok) throw new ParticipantClientError(code);
}
export function exact(
  v: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  requireWire(
    v &&
      typeof v === "object" &&
      !Array.isArray(v) &&
      Object.getPrototypeOf(v) === Object.prototype &&
      Object.keys(v).length === keys.length &&
      keys.every((k) => Object.hasOwn(v, k)),
  );
  return v as Record<string, unknown>;
}
export function identifier(v: unknown, max = 200): v is string {
  return typeof v === "string" && v.trim().length > 0 && v.length <= max;
}
function timestamp(v: unknown): asserts v is string {
  requireWire(
    typeof v === "string" && v.length <= 64 && Number.isFinite(Date.parse(v)),
  );
}
export function canonical(v: unknown): string {
  if (
    v === null ||
    typeof v === "string" ||
    typeof v === "boolean" ||
    typeof v === "number"
  )
    return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  return (
    "{" +
    Object.keys(v as object)
      .sort()
      .map(
        (k) =>
          JSON.stringify(k) +
          ":" +
          canonical((v as Record<string, unknown>)[k]),
      )
      .join(",") +
    "}"
  );
}
export async function hash(v: unknown): Promise<string> {
  return Array.from(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(canonical(v)),
      ),
    ),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
}
function sha(v: unknown) {
  requireWire(typeof v === "string" && /^[a-f0-9]{64}$/.test(v));
}
function ref(scope: Scope, v: unknown, kind?: string): Ref {
  const r = exact(v, ["tenantId", "projectId", "kind", "id", "revision"]);
  requireWire(
    r.tenantId === scope.tenantId &&
      r.projectId === scope.projectId &&
      identifier(r.kind, 100) &&
      identifier(r.id) &&
      Number.isSafeInteger(r.revision) &&
      (r.revision as number) > 0 &&
      (kind === undefined || r.kind === kind),
  );
  return v as Ref;
}
function binding(scope: Scope, v: unknown, kind?: string) {
  const b = exact(v, ["ref", "digest"]);
  ref(scope, b.ref, kind);
  sha(b.digest);
}
const termKeys = [
  "resource",
  "actions",
  "purposes",
  "audiences",
  "validFrom",
  "expiresAt",
  "evidence",
];
function terms(scope: Scope, v: unknown) {
  const t = exact(v, termKeys);
  binding(scope, t.resource);
  ref(scope, t.evidence);
  for (const k of ["actions", "purposes", "audiences"]) {
    const list = t[k];
    requireWire(
      Array.isArray(list) &&
        list.length > 0 &&
        list.length <= 32 &&
        list.every((x) => identifier(x) && x !== "*") &&
        new Set(list).size === list.length,
    );
  }
  requireWire(
    (t.actions as string[]).every((x) =>
      [
        "metadata-citation",
        "reproduce",
        "transform",
        "train",
        "distribute",
      ].includes(x),
    ),
  );
  timestamp(t.validFrom);
  timestamp(t.expiresAt);
  requireWire(Date.parse(t.validFrom) < Date.parse(t.expiresAt));
}
export async function checkedOffer(
  scope: Scope,
  v: unknown,
): Promise<ConsentOffer> {
  const o = exact(v, [
    "id",
    "subjectId",
    "terms",
    "disclosure",
    "responseExpiresAt",
    "ref",
    "createdAt",
    "createdBy",
    "status",
    "resolvedAt",
    "resolvedBy",
    "consent",
  ]);
  requireWire(
    identifier(o.id) &&
      identifier(o.subjectId) &&
      identifier(o.disclosure, 16000) &&
      identifier(o.createdBy),
  );
  const r = ref(scope, o.ref, "consent-offer");
  requireWire(r.id === o.id);
  terms(scope, o.terms);
  timestamp(o.createdAt);
  timestamp(o.responseExpiresAt);
  const t = o.terms as PermissionTerms;
  requireWire(
    Date.parse(o.createdAt) < Date.parse(o.responseExpiresAt) &&
      Date.parse(o.responseExpiresAt) <= Date.parse(t.expiresAt),
  );
  if (o.status === "offered") {
    requireWire(
      r.revision === 1 &&
        o.resolvedAt === null &&
        o.resolvedBy === null &&
        o.consent === null,
    );
  } else {
    requireWire(
      ["accepted", "declined", "cancelled"].includes(o.status as string) &&
        r.revision === 2 &&
        identifier(o.resolvedBy),
    );
    timestamp(o.resolvedAt);
    requireWire(Date.parse(o.resolvedAt) >= Date.parse(o.createdAt));
    if (o.status !== "cancelled")
      requireWire(Date.parse(o.resolvedAt) < Date.parse(o.responseExpiresAt));
    if (o.status === "accepted") {
      binding(scope, o.consent, "consent");
      const originalRef = { ...r, revision: 1 };
      const consentId = await hash({
        profile: "offer-consent-v1",
        offer: originalRef,
      });
      const capture: Consent = {
        ...t,
        ref: { ...scope, kind: "consent", id: consentId, revision: 1 },
        subjectId: o.subjectId as string,
        withdrawnAt: null,
        recordedBy: o.resolvedBy as string,
      };
      requireWire(
        canonical(o.consent) ===
          canonical({ ref: capture.ref, digest: await hash(capture) }),
      );
    } else requireWire(o.consent === null);
  }
  return v as ConsentOffer;
}
export function checkedConsent(scope: Scope, v: unknown): Consent {
  const c = exact(v, [
    ...termKeys,
    "ref",
    "subjectId",
    "withdrawnAt",
    "recordedBy",
  ]);
  const r = ref(scope, c.ref, "consent");
  terms(scope, Object.fromEntries(termKeys.map((k) => [k, c[k]])));
  requireWire(identifier(c.subjectId) && identifier(c.recordedBy));
  if (c.withdrawnAt === null) requireWire(r.revision === 1);
  else {
    timestamp(c.withdrawnAt);
    requireWire(r.revision === 2);
  }
  return v as Consent;
}
export async function checkedReview(
  scope: Scope,
  id: string,
  v: unknown,
): Promise<ParticipantReview> {
  const r = exact(v, [
    "offer",
    "reviewDigest",
    "responseOpen",
    "consent",
    "warnings",
  ]);
  const offer = await checkedOffer(scope, r.offer);
  requireWire(
    offer.id === id &&
      typeof r.responseOpen === "boolean" &&
      (!r.responseOpen || offer.status === "offered") &&
      Array.isArray(r.warnings) &&
      r.warnings.length <= 16 &&
      r.warnings.every((x) => identifier(x, 2000)),
  );
  requireWire(
    r.reviewDigest ===
      (await hash({ profile: "participant-consent-offer-v1", offer })),
  );
  if (offer.status === "accepted") {
    const c = checkedConsent(scope, r.consent);
    if (c.withdrawnAt !== null)
      requireWire(Date.parse(c.withdrawnAt) >= Date.parse(offer.resolvedAt!));
    requireWire(
      canonical({ ...c, ref: { ...c.ref, revision: 1 }, withdrawnAt: null }) ===
        canonical({
          ...offer.terms,
          ref: offer.consent!.ref,
          subjectId: offer.subjectId,
          withdrawnAt: null,
          recordedBy: offer.resolvedBy,
        }),
    );
  } else requireWire(r.consent === null);
  return v as ParticipantReview;
}
