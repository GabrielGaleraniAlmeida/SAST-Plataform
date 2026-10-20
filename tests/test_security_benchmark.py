import json
from pathlib import Path

from services.analyzer.app.engine.scanner import SASTScanner


def test_documented_taint_corpus_metrics(capsys):
    cases = json.loads(
        (Path(__file__).parent / "fixtures" / "taint_cases.json").read_text(encoding="utf-8")
    )
    scanner = SASTScanner()
    true_positive = false_positive = false_negative = true_negative = 0
    for case in cases:
        findings, flows = scanner._scan_snippet(
            case["code"], "python", f"{case['id']}.py"
        )
        actual_finding = any(finding["rule_id"] == "SAST-TAINT-001" for finding in findings)
        expected_finding = case["expected_finding"]
        if expected_finding and actual_finding:
            true_positive += 1
        elif expected_finding:
            false_negative += 1
        elif actual_finding:
            false_positive += 1
        else:
            true_negative += 1
        if "expected_sanitized" in case:
            assert flows
            assert all(flow["is_sanitized"] for flow in flows)
            assert not actual_finding

    print(
        "Measured taint-finding corpus: "
        f"TP={true_positive}, FP={false_positive}, FN={false_negative}, TN={true_negative}"
    )
    assert false_positive == 0
    assert false_negative == 0
