# Private GitHub Sharing Checklist

Use this export folder as the repository root:

```bash
cd <ashiba_receipt_compiler_private_preview>
```

Before inviting a reviewer:

1. Run the verification gate in `README.md`.
2. Run a local secret/internal-note scan and confirm it has no real findings.
3. Create a private GitHub repository.
4. Push only this export folder, not the parent Ashiba Compute workspace.
5. Invite reviewers with read-only access unless they are actively contributing.

Suggested first message:

```text
This is a private technical preview of Ashiba's local receipt compiler. The
fastest path is `./demo_30s.sh`, then `./ashiba scan ... --report`, then
`./compile ... --card`. The important behavior is that missing operational
evidence becomes an actionable `unknown`, not a weak affirmative claim.
```

Do not present this as a production security certification product.
