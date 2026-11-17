import asyncio
import datetime
import logging
import random
import threading
import time
from collections import deque
from typing import Dict, List, Optional

try:
    from rules.engine import evaluate_flow as _rules_evaluate_flow
    from rules.engine import compute_rule_score as _rules_compute_score
    from rules.risk_score import compute_risk_score as _compute_risk_score
    _RULES_AVAILABLE = True
except ImportError:
    _RULES_AVAILABLE = False

logger = logging.getLogger(__name__)


def _normalise_event(raw: Dict) -> Dict:
    """
    Translate a NetworkMonitor callback dict to the /ws/alerts wire schema.
    NetworkMonitor emits: type, is_alert, prediction, confidence, shap_factors, ...
    We emit:             kind, is_attack, attack_prob, shap_top3, ...
    """
    event_type = raw.get("type", "")

    if event_type == "monitor_replay_done":
        return {
            "kind": "replay_done",
            "total_flows": raw.get("total_flows", 0),
            "elapsed_seconds": raw.get("elapsed", 0),
        }

    if event_type == "monitor_error":
        return {
            "kind": "error",
            "message": raw.get("message", "Unknown monitor error"),
        }

    # monitor_event — a classified flow
    is_attack = bool(raw.get("is_alert", False))
    shap_raw = raw.get("shap_factors") or []
    shap_top3 = (
        [{"feature": f["feature"], "value": f["shap_value"], "direction": f.get("direction", "attack")}
         for f in shap_raw[:3]]
        if is_attack and shap_raw
        else None
    )

    attack_prob = float(raw.get("confidence", 0.0))
    # Confidence in the decision actually reached: P(attack) for an attack,
    # P(benign) = 1 - P(attack) for a benign flow. Without this a confident
    # benign flow (P attack = 4%) would display as "4%" and drag the average down.
    decision_conf = attack_prob if is_attack else 1.0 - attack_prob

    normalised = {
        "kind":       "flow",
        "src_ip":     raw.get("src_ip"),
        "src_port":   raw.get("src_port"),
        "dst_ip":     raw.get("dst_ip"),
        "dst_port":   raw.get("dst_port"),
        "timestamp":  raw.get("timestamp"),
        "is_attack":  is_attack,
        "prediction": raw.get("prediction", "Unknown"),
        "attack_prob": attack_prob,
        "confidence": decision_conf,
        "shap_top3":  shap_top3,
        "true_type":  raw.get("true_type"),
        "features":   raw.get("features"),
    }

    try:
        if _RULES_AVAILABLE:
            flow_meta = {
                "dst_port":                   int(raw.get("dst_port", 0) or 0),
                "syn_flag_count":             float(raw.get("syn_flag_count", 0) or 0),
                "ack_flag_count":             float(raw.get("ack_flag_count", 0) or 0),
                "connections_per_second":     float(raw.get("connections_per_second", 0) or 0),
                "distinct_dst_ports":         int(raw.get("distinct_dst_ports", 0) or 0),
                "connections_to_brute_ports": int(raw.get("connections_to_brute_ports", 0) or 0),
                "flow_packets_per_s":         float(raw.get("flow_packets_per_s", 0) or 0),
            }

            matches = _rules_evaluate_flow(flow_meta)
            rule_score = _rules_compute_score(matches)
            risk = _compute_risk_score(attack_prob, rule_score)

            explanation: List[str] = []
            for factor in shap_raw[:3]:
                feature = factor.get("feature", "unknown")
                direction = factor.get("direction", "attack")
                shap_val = float(factor.get("shap_value", 0.0))
                explanation.append(
                    f"Feature {feature} pushed the score {direction} (SHAP contribution: {shap_val:.3f})"
                )
            for m in matches:
                explanation.append(m.reason)

            normalised["risk_score"] = risk["score"]
            normalised["risk_level"] = risk["level"]
            normalised["matched_rules"] = [
                {"rule_id": m.rule_id, "severity": m.severity, "reason": m.reason}
                for m in matches
            ]
            normalised["explanation"] = explanation
        else:
            normalised["risk_score"] = 0
            normalised["risk_level"] = "LOW"
            normalised["matched_rules"] = []
            normalised["explanation"] = []
    except Exception as _rule_exc:
        logger.debug("Rule engine enrichment failed (non-fatal): %s", _rule_exc)
        normalised.setdefault("risk_score", 0)
        normalised.setdefault("risk_level", "LOW")
        normalised.setdefault("matched_rules", [])
        normalised.setdefault("explanation", [])

    return normalised


class MonitorService:
    """Wraps NetworkMonitor, normalises events, drives AlertStore + WebSocket broadcast."""

    def __init__(self):
        self._monitor = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._mode: Optional[str] = None
        self._source: Optional[str] = None
        self._start_time: Optional[float] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        self._alert_store = None
        self._alerts_manager = None
        self._stats_manager = None

        self._traffic_lock = threading.Lock()
        self._traffic_buckets: deque = deque(maxlen=60)
        self._traffic_labels: deque = deque(maxlen=60)
        self._confidence_sum = 0.0
        self._flow_count = 0

        # Remote "live" session (flows fed from the VM over the host-only network).
        self._remote_q = None
        self._remote_rate = 0.6
        self._model_ref = None
        self._explainer_ref = None

    def configure(self, alert_store, alerts_manager, stats_manager, loop):
        self._alert_store = alert_store
        self._alerts_manager = alerts_manager
        self._stats_manager = stats_manager
        self._loop = loop

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def mode(self) -> Optional[str]:
        return self._mode

    @property
    def source(self) -> Optional[str]:
        return self._source

    def start(self, model, preprocessor, explainer, mode: str,
              interface: Optional[str] = None, pcap_path: Optional[str] = None,
              threshold: float = 0.5):
        if self._running:
            return

        from src.monitor import NetworkMonitor

        self._mode = mode
        self._source = pcap_path if mode == "replay" else interface
        self._start_time = time.time()

        self._monitor = NetworkMonitor(
            model=model,
            preprocessor=preprocessor,
            explainer=explainer,
            event_callback=self._on_event,
            threshold=threshold,
        )

        def _run():
            try:
                if mode == "replay" and pcap_path:
                    self._monitor.start_replay(pcap_path)
                else:
                    self._monitor.start_live(interface=interface)
            except Exception as e:
                self._on_event({"type": "monitor_error", "message": str(e)})
            finally:
                self._running = False

        self._running = True
        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()

    def start_dataset_replay(self, model, explainer, X, labels=None, rate: float = 0.6):
        """
        Demonstration mode: stream real dataset rows through the live pipeline.

        Each row is classified by the real model and (for attacks) explained by
        the real SHAP explainer, then pushed through the normal alert path so the
        dashboard lights up exactly as it would for live capture — but with
        in-distribution data the model reliably detects. Used to demonstrate
        detection + explanation end to end.
        """
        if self._running:
            return

        self._mode = "replay"
        self._source = "dataset replay"
        self._start_time = time.time()
        self._running = True

        def _run():
            try:
                for i in range(len(X)):
                    if not self._running:
                        break
                    row = X[i:i + 1]
                    proba = model.predict_proba(row)[0]
                    pred_code = int(model.predict(row)[0])
                    prediction = "Attack" if pred_code == 1 else "Benign"
                    is_alert = pred_code == 1

                    shap_factors = []
                    if is_alert and explainer is not None and getattr(explainer, "is_ready", False):
                        try:
                            expl = explainer.explain(row, method="shap")
                            se = expl.get("shap_explanation") or {}
                            for c in se.get("contributions", [])[:3]:
                                shap_factors.append({
                                    "feature": c["feature"],
                                    "shap_value": round(float(c["shap_value"]), 4),
                                    "direction": c["direction"],
                                })
                        except Exception as e:
                            logger.debug("Replay SHAP failed: %s", e)

                    raw = {
                        "type": "monitor_event",
                        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                        "src_ip": f"203.0.113.{random.randint(2, 254)}",
                        "src_port": random.randint(1024, 65535),
                        "dst_ip": "192.168.1.10",
                        "dst_port": random.choice([80, 443, 22, 21, 3389, 8080]),
                        "protocol": "TCP",
                        "prediction": prediction,
                        "confidence": float(proba[1]),
                        "is_alert": is_alert,
                        "shap_factors": shap_factors,
                        "true_type": labels[i] if (labels is not None and i < len(labels)) else None,
                        "features": row[0].tolist(),
                    }
                    self._on_event(raw)
                    time.sleep(rate)
            except Exception as e:
                logger.error("Dataset replay error: %s", e, exc_info=True)
            finally:
                self._running = False
                self._broadcast(_normalise_event({"type": "monitor_replay_done"}), "alerts")

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()

    def _make_event(self, model, explainer, row, true_type=None):
        """Classify one feature vector and build a monitor_event (with inline SHAP for attacks)."""
        import numpy as np
        x = np.asarray(row, dtype=np.float32).reshape(1, -1)
        proba = model.predict_proba(x)[0]
        pred_code = int(model.predict(x)[0])
        prediction = "Attack" if pred_code == 1 else "Benign"
        is_alert = pred_code == 1

        shap_factors = []
        if is_alert and explainer is not None and getattr(explainer, "is_ready", False):
            try:
                expl = explainer.explain(x, method="shap")
                se = expl.get("shap_explanation") or {}
                for c in se.get("contributions", [])[:3]:
                    shap_factors.append({"feature": c["feature"],
                                         "shap_value": round(float(c["shap_value"]), 4),
                                         "direction": c["direction"]})
            except Exception as e:
                logger.debug("Remote SHAP failed: %s", e)

        return {
            "type": "monitor_event",
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
            "src_ip": f"192.168.179.{random.randint(2, 254)}",
            "src_port": random.randint(1024, 65535),
            "dst_ip": "192.168.179.1",
            "dst_port": random.choice([80, 443, 22, 21, 3389, 8080]),
            "protocol": "TCP",
            "prediction": prediction,
            "confidence": float(proba[1]),
            "is_alert": is_alert,
            "shap_factors": shap_factors,
            "true_type": true_type,
            "features": x[0].tolist(),
        }

    def start_remote(self, model, explainer, source_label="VMware Host-Only (Kali)", rate: float = 0.6):
        """Begin a 'live' session that classifies flows fed in from the VM (over HTTP).
        Presented to the dashboard exactly like live capture on a network interface."""
        if self._running:
            return False
        import queue
        self._mode = "live"
        self._source = source_label
        self._start_time = time.time()
        self._running = True
        self._remote_rate = max(0.0, float(rate))
        self._remote_q = queue.Queue()
        self._model_ref = model
        self._explainer_ref = explainer
        self._monitor = None
        self._thread = threading.Thread(target=self._remote_loop, daemon=True, name="monitor-remote")
        self._thread.start()
        return True

    def feed_remote(self, X, labels=None):
        """Queue feature vectors (from the VM) to be streamed through the live pipeline."""
        if not self._running or self._remote_q is None:
            return 0
        n = 0
        for i in range(len(X)):
            label = labels[i] if (labels is not None and i < len(labels)) else None
            self._remote_q.put((X[i], label))
            n += 1
        return n

    def _remote_loop(self):
        import queue
        model, explainer = self._model_ref, self._explainer_ref
        while self._running:
            try:
                row, label = self._remote_q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._on_event(self._make_event(model, explainer, row, true_type=label))
                if self._remote_rate:
                    time.sleep(self._remote_rate)
            except Exception as e:
                logger.debug("Remote loop error: %s", e)

    def stop(self):
        if self._monitor:
            self._monitor.stop()
        self._running = False

    def status(self) -> Dict:
        store_stats = self._alert_store.stats() if self._alert_store else {}
        uptime = int(time.time() - self._start_time) if self._start_time and self._running else 0
        return {
            "running": self._running,
            "mode": self._mode,
            "source": self._source,
            "uptime_seconds": uptime,
            "total_flows": store_stats.get("total", 0),
            "attacks": store_stats.get("attacks", 0),
            "benign": store_stats.get("benign", 0),
        }

    def get_stats_payload(self) -> Dict:
        store_stats = self._alert_store.stats() if self._alert_store else {}
        total = store_stats.get("total", 0)
        attacks = store_stats.get("attacks", 0)
        benign = store_stats.get("benign", 0)
        threat_rate = round(attacks / total, 4) if total else 0.0

        with self._traffic_lock:
            history = list(self._traffic_buckets)
            labels = list(self._traffic_labels)

        return {
            "total_flows": total,
            "attacks": attacks,
            "benign": benign,
            "threat_rate": threat_rate,
            "avg_confidence": round(self._confidence_sum / self._flow_count, 4) if self._flow_count else 0.0,
            "active_flows": 0,
            "uptime_seconds": int(time.time() - self._start_time) if self._start_time else 0,
            "packets_per_sec": 0,
            "traffic_history": history,
            "traffic_labels": labels,
        }

    def _on_event(self, raw: Dict):
        """Called from the monitor thread. Must be thread-safe."""
        normalised = _normalise_event(raw)

        if normalised["kind"] in ("replay_done", "error"):
            self._broadcast(normalised, channel="alerts")
            if normalised["kind"] == "replay_done":
                self._running = False
            return

        alert = self._alert_store.push(normalised)
        # Don't broadcast the full feature vector — it's only needed server-side for LIME.
        wire = {k: v for k, v in alert.items() if k != "features"}
        self._broadcast(wire, channel="alerts")

        with self._traffic_lock:
            # Average the confidence of the decision reached, not P(attack),
            # so a benign-heavy stream doesn't show a misleadingly low average.
            self._confidence_sum += float(normalised.get("confidence", 0.0))
            self._flow_count += 1
            label = datetime.datetime.now().strftime("%H:%M:%S")
            if self._traffic_labels and self._traffic_labels[-1] == label:
                self._traffic_buckets[-1] += 1
            else:
                self._traffic_buckets.append(1)
                self._traffic_labels.append(label)

    def _broadcast(self, message: Dict, channel: str):
        if not self._loop:
            return
        manager = self._alerts_manager if channel == "alerts" else self._stats_manager
        if manager:
            asyncio.run_coroutine_threadsafe(manager.broadcast(message), self._loop)


# Global singleton
monitor_service = MonitorService()
