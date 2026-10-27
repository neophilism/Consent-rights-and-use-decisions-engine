# Rights and consent boundary

Every decision binds an exact resource edition and digest, requested action, purpose, audience, attribution and permission time window. Metadata citation, reproduction, transformation, training and distribution are separate actions. Explicit consent is required for every declared participant subject. Permission evidence records who supplied it; software cannot establish that a signer owned the rights.

Grant and consent creation require human-supplied evidence. Withdrawal creates a new revision and preserves the old record. Consumers must provide only current permission revisions from trusted storage. Mixing revisions of one permission fails closed; a withdrawn or expired current permission cannot authorize use. Missing rights are denied, never inferred from public accessibility.

The package provides the durable permission registry and participant offer workflow described below. A hosted participant portal, independent rights verification service and public publisher are not provided. The deployment authorization gateway must authorize every permission mutation, including withdrawal and participant-specific authority. A rights grant never substitutes for an owner release decision.

## Durable permission registry

The registry adapter consumes a pinned Evidence persistence SDK in a dedicated permission database. It never reads/writes the operational Evidence or intake databases. Current permission records and immutable revisions, audit and withdrawal-impact outbox records commit in one restricted-role transaction. Replay keys bind commands to authenticated actor and exact input. Evaluations load current permissions rather than accepting obsolete permission objects from a caller.

A scope-bound deployment policy identifies human permission managers and participant-to-subject identity bindings. Participants can consent/withdraw only for their bound subjects and cannot grant rights. Resource editions and bytes are fixed; existing consent requirements cannot be removed from later editions. Derived-resource lineage restrictions must be supplied by the trusted resource registration gateway. Permission evidence still needs real verification; storage does not prove ownership or valid legal consent.

Real PGlite tests apply the pinned SDK migration and use a restricted login, with manager/participant authority, withdrawal, replay, scope and rollback cases. Embedded tests do not establish real network-session contention or live deployment acceptance; the separate disposable network suite is described below. Production must provision a separate migration role and restricted login, and protect identity/participant mappings.

## Participant offer workflow

[Participant offers](PARTICIPANTS.md) separate manager-authored proposals from authenticated participant responses. A response binds the viewed stored revision and disclosure/terms digest. Acceptance, consent creation, resolved proposal, audit assertion and response event are transactional. Decline/cancel do not grant permission. Participant review returns current consent after withdrawal while retaining the original capture receipt. Cached response and withdrawal receipts require current participant/manager authority; replay cannot restore withdrawn consent. This is trusted library orchestration, not a hosted identity service or an atomic fence across downstream uses.

## Participant HTTP adapter

The opt-in [private participant handler](PARTICIPANT_HTTP.md) adds host-authenticated session, exact offer review, response and own-consent withdrawal routes over the accepted durable registry. It restricts Origin/Fetch Metadata, binds writes to session CSRF and bounds authentication/body admission. It does not provide login, send invitations, expose manager commands or authorize release. An actual host and participant UI still require qualification.

## Serialized current permission decisions

Permission evaluation acquires the SDK project lock with a checked audit before loading the resource or any permission editions, serializing those reads with withdrawal and other writes. This fixes a reproduced network-session stale-decision race where an evaluation read old consent and only then waited for withdrawal at its final audit. The final decision/hash audit remains. Decisions describe the SQL snapshot and caller-supplied trusted time; they are not future action permits or atomic fences across external consumers. [PostgreSQL tests](POSTGRES_TESTS.md) distinguish actual disposable-session evidence from host identity/time, rights verification and production qualification.

Participant HTTP authentication and body admission now use monotonic checks around metadata/callback/session validation and stream/UTF8 stages, closing every auth signal. Three actual restricted-migration regressions reproduced session/consent acceptance after blocked-JS timeouts on old main. Fixed acceptance does not preempt callbacks or change begun-SQL uncertainty, request ordering or deployment identity trust.
