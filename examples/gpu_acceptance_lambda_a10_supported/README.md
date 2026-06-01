# Lambda A10 Acceptance Packet

Redacted demo fixture derived from a real Lambda Labs `1x A10 (24 GB PCIe)`
instance capture on 2026-05-31.

The dashboard evidence included `1x A10 (24 GB PCIe)`. This fixture declares the
family-level `A10` claim because the captured `nvidia-smi` name exposed
`NVIDIA A10` and did not expose the PCIe variant string. A literal `A10-PCIe`
declaration correctly compiles to `UNKNOWN` on this packet.

Raw stable hardware identifiers, serials, UUIDs, SSH details, and account details
are omitted.
