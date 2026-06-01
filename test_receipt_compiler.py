#!/usr/bin/env python3
"""Compatibility runner for the split receipt compiler smoke tests."""

from __future__ import annotations

from test_authorization_flows import run_authorization_flow_tests
from test_claim_contracts import run_claim_contract_tests
from test_execution_contexts import run_execution_context_tests
from test_gallery import run_gallery_tests
from test_gpu_acceptance import run_gpu_acceptance_tests
from test_gpu_collateral import run_gpu_collateral_tests
from test_importers import run_importer_tests
from test_receipt_core import run_receipt_core_tests
from test_scan import run_scan_tests


def main() -> int:
    run_receipt_core_tests()
    run_claim_contract_tests()
    run_execution_context_tests()
    run_gpu_collateral_tests()
    run_authorization_flow_tests()
    run_importer_tests()
    run_gpu_acceptance_tests()
    run_scan_tests()
    run_gallery_tests()
    print("receipt compiler smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
