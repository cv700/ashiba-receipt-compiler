# Not Another Logging Standard

The most important design constraint is that users should not have to adopt a
new input format before the tool is useful.

Ashiba reads evidence that teams already have:

- CloudTrail
- OpenTelemetry
- GitHub Actions
- Kubernetes audit logs
- SIEM JSONL
- OpenAI, Anthropic, LangSmith, and agent tool-call traces
- approval, review, and policy exports

The receipt is an output artifact, not an input requirement.

## What Ashiba Is Not Replacing

Ashiba does not replace:

- CloudTrail
- OpenTelemetry
- Sigstore
- SLSA
- TEEs
- SIEM logs
- SOC 2 evidence collection
- ISO or GRC workflows
- agent observability tools

Those systems produce or organize evidence. Ashiba asks a narrower question:

```text
Given this evidence, can we support this operational claim?
```

## The Useful Difference

Most evidence systems can show that something was logged.

Ashiba tries to show whether the logged evidence is enough to decide a claim.

If it is not enough, the output should be actionable:

```text
authorization_bound_action: unknown
missing: authorization.revoked_at
next probe: add revocation_state export
```

That is the wedge. The user learns what to instrument next without first
learning a new ontology.

## The Hard Rule

If the scanner says a packet is not receipt-ready for a claim, the compiler must
not emit `supported` for that same claim on that same packet.

This prevents the receipt layer from becoming decorative compliance output. It
has to fail closed when the evidence is not strong enough.
