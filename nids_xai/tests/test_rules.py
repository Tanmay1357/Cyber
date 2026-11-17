"""
Tests for the NIDS-XAI rule engine and risk scorer.

Run from the repo root:
    pytest nids_xai/tests/test_rules.py -v
Or via the venv:
    nids_xai/venv/Scripts/pytest nids_xai/tests/test_rules.py -v
"""

import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Ensure `from rules.xxx import ...` and `from config.xxx import ...` resolve
# regardless of invocation directory (mirrors conftest.py style).
# ---------------------------------------------------------------------------
_NIDS_DIR = Path(__file__).resolve().parent.parent
if str(_NIDS_DIR) not in sys.path:
    sys.path.insert(0, str(_NIDS_DIR))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def port_scan_flow():
    """A flow that should trigger PORTSCAN_01 (>= 50 distinct dst ports)."""
    return {
        "src_ip": "10.0.0.1",
        "dst_port": 80,
        "syn_flag_count": 2,
        "ack_flag_count": 1,
        "connections_per_second": 1.0,
        "distinct_dst_ports": 60,       # above threshold of 50
        "connections_to_brute_ports": 0,
        "flow_packets_per_s": 5.0,
    }


@pytest.fixture
def brute_force_flow():
    """A flow that should trigger BRUTEFORCE_01 (>= 20 connections to brute ports)."""
    return {
        "src_ip": "10.0.0.2",
        "dst_port": 22,
        "syn_flag_count": 5,
        "ack_flag_count": 2,
        "connections_per_second": 2.0,
        "distinct_dst_ports": 1,
        "connections_to_brute_ports": 25,  # above threshold of 20
        "flow_packets_per_s": 10.0,
    }


@pytest.fixture
def benign_flow():
    """A flow with all metrics well below every threshold."""
    return {
        "src_ip": "10.0.0.3",
        "dst_port": 443,
        "syn_flag_count": 1,
        "ack_flag_count": 5,
        "connections_per_second": 0.5,
        "distinct_dst_ports": 2,
        "connections_to_brute_ports": 0,
        "flow_packets_per_s": 3.0,
    }


# ---------------------------------------------------------------------------
# Rule engine tests
# ---------------------------------------------------------------------------

class TestEvaluateFlow:
    def test_port_scan_matches(self, port_scan_flow):
        from rules.engine import evaluate_flow

        matches = evaluate_flow(port_scan_flow)
        rule_ids = [m.rule_id for m in matches]
        assert "PORTSCAN_01" in rule_ids, (
            f"Expected PORTSCAN_01 to match; matched rules: {rule_ids}"
        )

    def test_brute_force_matches(self, brute_force_flow):
        from rules.engine import evaluate_flow

        matches = evaluate_flow(brute_force_flow)
        rule_ids = [m.rule_id for m in matches]
        assert "BRUTEFORCE_01" in rule_ids, (
            f"Expected BRUTEFORCE_01 to match; matched rules: {rule_ids}"
        )

    def test_benign_no_matches(self, benign_flow):
        from rules.engine import evaluate_flow

        matches = evaluate_flow(benign_flow)
        assert len(matches) == 0, (
            f"Expected no rule matches for benign flow; got: {[m.rule_id for m in matches]}"
        )

    def test_dos_matches(self):
        from rules.engine import evaluate_flow

        dos_flow = {
            "src_ip": "10.0.0.4",
            "dst_port": 80,
            "syn_flag_count": 100,
            "ack_flag_count": 5,
            "connections_per_second": 100.0,  # above threshold of 50
            "distinct_dst_ports": 1,
            "connections_to_brute_ports": 0,
            "flow_packets_per_s": 200.0,
        }
        matches = evaluate_flow(dos_flow)
        rule_ids = [m.rule_id for m in matches]
        assert "DOS_01" in rule_ids

    def test_syn_flood_matches(self):
        from rules.engine import evaluate_flow

        syn_flow = {
            "src_ip": "10.0.0.5",
            "dst_port": 80,
            "syn_flag_count": 50,  # >= min_syn_count=10
            "ack_flag_count": 2,   # ratio = 25.0 >= threshold 5.0
            "connections_per_second": 5.0,
            "distinct_dst_ports": 1,
            "connections_to_brute_ports": 0,
            "flow_packets_per_s": 50.0,
        }
        matches = evaluate_flow(syn_flow)
        rule_ids = [m.rule_id for m in matches]
        assert "SYN_FLOOD_01" in rule_ids

    def test_match_has_reason_string(self, port_scan_flow):
        from rules.engine import evaluate_flow

        matches = evaluate_flow(port_scan_flow)
        for m in matches:
            assert isinstance(m.reason, str) and len(m.reason) > 0


class TestComputeRuleScore:
    def test_no_matches_gives_zero(self):
        from rules.engine import compute_rule_score

        assert compute_rule_score([]) == 0.0

    def test_critical_gives_one(self):
        from rules.engine import RuleMatch, compute_rule_score

        matches = [RuleMatch(matched=True, rule_id="DOS_01", severity="CRITICAL", reason="x")]
        assert compute_rule_score(matches) == 1.0

    def test_max_severity_taken(self):
        from rules.engine import RuleMatch, compute_rule_score

        matches = [
            RuleMatch(matched=True, rule_id="PORTSCAN_01", severity="HIGH", reason="x"),
            RuleMatch(matched=True, rule_id="DOS_01", severity="CRITICAL", reason="y"),
        ]
        assert compute_rule_score(matches) == 1.0


# ---------------------------------------------------------------------------
# Risk score tests
# ---------------------------------------------------------------------------

class TestComputeRiskScore:
    def test_max_scores_give_critical(self):
        from rules.risk_score import compute_risk_score

        result = compute_risk_score(1.0, 1.0)
        assert result["score"] >= 90, f"Expected CRITICAL (>=90), got {result['score']}"
        assert result["level"] == "CRITICAL"

    def test_zero_scores_give_low(self):
        from rules.risk_score import compute_risk_score

        result = compute_risk_score(0.0, 0.0)
        assert result["score"] <= 39, f"Expected LOW (<=39), got {result['score']}"
        assert result["level"] == "LOW"

    def test_mid_scores_give_medium(self):
        from rules.risk_score import compute_risk_score

        result = compute_risk_score(0.5, 0.5)
        assert 40 <= result["score"] <= 69, (
            f"Expected MEDIUM (40-69), got {result['score']}"
        )
        assert result["level"] == "MEDIUM"

    def test_score_clamped_at_100(self):
        from rules.risk_score import compute_risk_score

        result = compute_risk_score(2.0, 2.0)  # intentionally out-of-range inputs
        assert result["score"] <= 100

    def test_score_clamped_at_0(self):
        from rules.risk_score import compute_risk_score

        result = compute_risk_score(-1.0, -1.0)  # intentionally out-of-range inputs
        assert result["score"] >= 0

    def test_returns_dict_with_expected_keys(self):
        from rules.risk_score import compute_risk_score

        result = compute_risk_score(0.8, 0.5)
        assert "score" in result
        assert "level" in result
        assert isinstance(result["score"], int)
        assert result["level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
