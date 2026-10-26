# Rights and consent boundary

Every decision binds an exact resource edition and digest, requested action, purpose, audience, attribution and permission time window. Metadata citation, reproduction, transformation, training and distribution are separate actions. Explicit consent is required for every declared participant subject. Permission evidence records who supplied it; software cannot establish that a signer owned the rights.

Grant and consent creation require human-supplied evidence. Withdrawal creates a new revision and preserves the old record. Consumers must provide only current permission revisions from trusted storage. Mixing revisions of one permission fails closed; a withdrawn or expired current permission cannot authorize use. Missing rights are denied, never inferred from public accessibility.

The initial library has no participant portal, persistent registry, rights verification service or public publisher. Those milestones remain planned. The deployment authorization gateway must authorize every permission mutation, including withdrawal and participant-specific authority. A rights grant never substitutes for an owner release decision.

## Durable permission registry

The registry adapter consumes a pinned Evidence persistence SDK in a dedicated permission database. It never reads/writes the operational Evidence or intake databases. Current permission records and immutable revisions, audit and withdrawal-impact outbox records commit in one restricted-role transaction. Replay keys bind commands to authenticated actor and exact input. Evaluations load current permissions rather than accepting obsolete permission objects from a caller.

A scope-bound deployment policy identifies human permission managers and participant-to-subject identity bindings. Participants can consent/withdraw only for their bound subjects and cannot grant rights. Resource editions and bytes are fixed; existing consent requirements cannot be removed from later editions. Derived-resource lineage restrictions must be supplied by the trusted resource registration gateway. Permission evidence still needs real verification; storage does not prove ownership or valid legal consent.

Real PGlite tests apply the pinned SDK migration and use a restricted login, with manager/participant authority, withdrawal, replay, scope and rollback cases. This does not claim real network-session contention or live deployment acceptance. Production must provision a separate migration role and restricted login, and protect identity/participant mappings.
