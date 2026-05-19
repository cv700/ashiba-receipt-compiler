# Customer CloudTrail Revocation-Gap Packet

This packet is a customer-style messy-log receipt bundle.

Scenario:

- A customer-support agent runtime invoked an AWS Lambda function that creates a
  refund case.
- The raw CloudTrail event and a shift-level authorization policy were dropped
  into the packet.
- The policy contains grant identity and grant-window fields, but the export
  does not include an explicit revocation-state field.

Expected receipt result:

- `authorization_bound_action` is `unknown`, not `contradicted`.
- The gap report should ask for `authorization.revoked_at` as either an ISO
  8601 UTC revocation timestamp or explicit `null` when checked and not revoked.
