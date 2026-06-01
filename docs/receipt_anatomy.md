# Receipt Anatomy

A receipt is a bounded decision artifact over existing evidence.

It is not a trace, a SIEM event, a SOC 2 control, an attestation, or a model
judgment. It is the compiler output that says whether a narrow operational
claim is supported, contradicted, unknown, or not applicable.

## Flow

```text
existing logs
  -> importers
  -> normalized artifacts
  -> claim pack
  -> deterministic passes
  -> bounded receipt
```

In this flow, a claim pack is the versioned verifier contract, not the evidence
itself. It defines the claim text, expected evidence paths, applicability paths,
support requirements, deterministic passes, pass parameters, and renderer
family. The receipt is the result of applying that contract to one normalized
artifact bundle.

## Fields

| Field | Meaning |
| --- | --- |
| `receipt_id` | Local identifier for this compiler output. |
| `created_at` | UTC time when the receipt was created. |
| `compiler_version` | Compiler version that produced the receipt. |
| `claim_type` | The claim family, such as `authorization_bound_action`. |
| `claim` | The exact statement being evaluated. |
| `expected_evidence` | Dotted paths that should exist before the claim can be supported. |
| `artifacts` | The normalized evidence the compiler actually checked. |
| `absence` | Missing expected evidence. Missing means `unknown`, not `contradicted`. |
| `pass_results` | Deterministic checks and their local effects. |
| `compiler_errors` | Failures in compilation, not failures of the system under review. |
| `verdict` | The final state: `supported`, `contradicted`, `unknown`, or `not_applicable`. |
| `boundary` | What the receipt supports and what it explicitly does not support. |
| `unsupported_inferences` | Claims a reader might overread from the receipt but should not. |
| `artifact_manifest` | Source files, byte sizes, and hashes for input binding. |
| `input_set_hash` | Hash over the input set used to produce the receipt. |
| `execution_context` | Optional domain-specific test context, such as GPU goodput conditions. |

## Verdicts

`supported` means the required evidence is present and the deterministic passes
support the claim.

`contradicted` means evidence conflicts with the claim. Example: execution time
is later than the grant expiry.

`unknown` means the compiler does not have enough evidence. Example:
`authorization.revoked_at` is missing, so non-revocation was not actually
observed.

`not_applicable` means the artifact class does not instantiate the claim. Example:
asking a deployment-review claim of a packet with no deployment evidence.

## Why Boundary Language Matters

Receipts are designed to stop overreading. A receipt can say:

```text
This action was contradicted by active-grant evidence.
```

It should not silently imply:

```text
The whole agent is unsafe.
The vendor is dishonest.
All other actions had the same problem.
The logs are authentic.
```

The boundary is part of the product, not legal boilerplate.
