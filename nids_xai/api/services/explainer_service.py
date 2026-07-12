import logging
import random
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Plain-English context for each feature.
# Each entry: (attack_context, benign_context)
_FEATURE_CONTEXT = {
    "SYN Flag Count":          ("a high SYN flag count is a hallmark of SYN flood attacks or port scanning, where many half-open connections are attempted",
                                 "the SYN flag count is within normal range for legitimate connections"),
    "RST Flag Count":          ("multiple connection resets suggest port scanning or repeated failed attack attempts",
                                 "the connection reset rate is within expected bounds"),
    "Flow Duration":           ("a very short connection duration is typical of automated scanning tools that rapidly probe many targets",
                                 "the connection duration is consistent with normal user or application behaviour"),
    "Fwd Packets/s":           ("an unusually high outgoing packet rate indicates possible flooding or rapid automated probing",
                                 "the outgoing packet rate is within expected range for this type of traffic"),
    "Bwd Packets/s":           ("an abnormal incoming packet rate may indicate a reflection or amplification attack",
                                 "the incoming packet rate matches normal traffic patterns"),
    "Flow Packets/s":          ("an extremely high overall packet rate is a common indicator of denial-of-service or scanning",
                                 "the overall packet rate is normal"),
    "Flow Bytes/s":            ("an extremely high data-transfer rate is characteristic of DoS flooding attacks",
                                 "the data-transfer rate matches legitimate traffic expectations"),
    "Destination Port":        ("the targeted port, combined with other suspicious indicators, suggests malicious intent",
                                 "the destination port is commonly used by legitimate services"),
    "URG Flag Count":          ("URG flags are rarely used in normal traffic; their presence may indicate tunnelling or evasion techniques",
                                 "the URG flag usage is normal"),
    "Packet Length Variance":  ("highly variable packet sizes can indicate packet injection or the use of attack tools",
                                 "packet size variation is consistent with normal traffic"),
    "Average Packet Size":     ("abnormal packet sizes may indicate protocol abuse or a non-standard client",
                                 "the average packet size matches expected legitimate traffic"),
    "Init_Win_bytes_forward":  ("an unusual initial TCP window size may indicate a non-standard or malicious client",
                                 "the TCP window size matches normal client behaviour"),
    "Init_Win_bytes_backward": ("an unusual server-side window size may indicate a misconfigured or spoofed response",
                                 "the server TCP window size is normal"),
    "ACK Flag Count":          ("unusual ACK patterns can indicate ACK flooding or scanning",
                                 "the ACK pattern is consistent with a normal TCP session"),
    "PSH Flag Count":          ("excessive PSH flags may indicate data injection or exfiltration",
                                 "the PSH flag count is normal"),
    "FIN Flag Count":          ("excessive FIN flags may indicate port scanning using half-close technique",
                                 "the FIN flag count is within expected range"),
    "Fwd Packet Length Max":   ("unusually large forwarded packets may indicate payload injection",
                                 "the maximum packet size is within normal bounds"),
    "Bwd Packet Length Max":   ("unusually large received packets may indicate a reflection amplification attack",
                                 "the maximum received packet size is normal"),
    "Flow IAT Mean":           ("very short inter-arrival times suggest automated, machine-speed traffic rather than human activity",
                                 "the packet timing matches typical human or application behaviour"),
    "Flow IAT Max":            ("irregular gaps between packets can indicate covert channel communication or slow scanning",
                                 "packet timing gaps are consistent with normal traffic"),
}


def _feature_context(feature_name: str, is_attack_direction: bool) -> str:
    """Return a plain-English sentence about why this feature matters."""
    # Try exact match, then partial
    for key, (atk_ctx, ben_ctx) in _FEATURE_CONTEXT.items():
        if key.lower() == feature_name.lower() or key.lower() in feature_name.lower():
            return atk_ctx if is_attack_direction else ben_ctx
    # Fallback wording: must match the direction. A benign-supporting feature
    # should read as normal, not suspicious.
    if is_attack_direction:
        return "this value stood out from typical legitimate traffic"
    return "this value was within the range expected for normal traffic"


def _build_shap_narrative(prediction: str, attack_prob: float, features: List[Dict]) -> str:
    """
    Generate a fuller plain-English explanation of a single decision. Each driver
    is given a strength word (strongly / moderately / slightly influential) based
    on how large its contribution is relative to the most influential feature, a
    plain reason, and the paragraph ends with an interpretation of what it means.
    """
    is_attack = prediction.upper() == "ATTACK"
    conf = attack_prob if is_attack else 1.0 - attack_prob
    pct = f"{conf * 100:.1f}%"

    # Ignore negligible (~0) contributions so the wording and counts reflect only
    # the features that actually influenced the decision.
    meaningful = [f for f in features if abs(f.get("shap_value", 0.0)) >= 0.005]
    if meaningful:
        features = meaningful

    attack_features = [f for f in features if f["direction"] == "positive"]
    benign_features = [f for f in features if f["direction"] == "negative"]
    top_mag = max((abs(f["shap_value"]) for f in features), default=1.0) or 1.0
    top_overall = max(features, key=lambda f: abs(f["shap_value"]), default=None)

    # Light wording variation so repeated explanations (and the SHAP vs LIME
    # panels) do not read as identical templates. The numbers and features stay
    # faithful to the model; only the prose varies.
    def strength(v):
        r = abs(v) / top_mag
        pool = (["strongly influential", "a major factor", "weighed heavily here"] if r >= 0.66 else
                ["moderately influential", "a noticeable factor", "carried moderate weight"] if r >= 0.33 else
                ["slightly influential", "a minor factor", "carried only a little weight"])
        return random.choice(pool)

    pick = random.choice
    plur = lambda n: "" if n == 1 else "s"
    lines = []

    if is_attack:
        opening = pick([
            f"The model flagged this connection as an ATTACK and is {pct} confident in that call.",
            f"This connection was classified as an ATTACK, with {pct} confidence.",
            f"With {pct} confidence, the model decided this connection is an ATTACK.",
        ])
        intro = pick([
            "The measurements that pushed it that way, in order of influence, were:",
            "The signals that weighed most towards an attack, strongest first, were:",
            "Ranked by how much they mattered, the attack indicators were:",
        ])
        lines += [opening + " " + intro, ""]
        for i, f in enumerate(attack_features[:5], 1):
            lines.append(f"  {i}. {f['feature']} ({strength(f['shap_value'])}) — {_feature_context(f['feature'], True)}.")
        if benign_features:
            nb = len(benign_features)
            lines.append("")
            if top_overall is not None and top_overall["direction"] == "negative":
                lines.append(pick([
                    f"Interestingly, the single strongest measurement, {top_overall['feature']}, actually "
                    f"leaned towards normal. The decision was still attack because the model weighs all the "
                    f"features together rather than any one alone, and a split like this is exactly why two "
                    f"methods are compared.",
                    f"Notably, the most influential signal here, {top_overall['feature']}, pointed towards "
                    f"normal traffic. The overall verdict was still attack, as the model combines every "
                    f"feature rather than relying on the strongest, which is why comparing two methods helps.",
                ]))
            else:
                top_b = max(benign_features, key=lambda f: abs(f["shap_value"]))
                lines.append(pick([
                    f"Not everything pointed to an attack: {nb} measurement{plur(nb)} looked normal, most "
                    f"notably {top_b['feature']}, but the attack evidence was stronger overall.",
                    f"A few signals leaned the other way ({nb} in total, led by {top_b['feature']}), yet they "
                    f"were outweighed by the indicators above.",
                ]))
        lines += ["", pick([
            "In short, this behaves more like automated or malicious activity than ordinary use, so the "
            "source and intent are worth checking.",
            "Overall, the pattern resembles attack traffic rather than normal use; investigating where it "
            "came from is advisable.",
            "Taken together, this looks like a malicious or automated connection, and it is worth a closer look.",
        ])]
    else:
        opening = pick([
            f"The model judged this connection to be NORMAL (benign), with {pct} confidence.",
            f"This connection was classified as NORMAL (benign); the model is {pct} confident.",
            f"With {pct} confidence, the model considers this connection normal (benign).",
        ])
        intro = pick([
            "The measurements that most supported that, in order of influence, were:",
            "The signals that weighed most towards normal traffic, strongest first, were:",
            "Ranked by how much they mattered, the indicators of normal traffic were:",
        ])
        lines += [opening + " " + intro, ""]
        for i, f in enumerate(benign_features[:5], 1):
            lines.append(f"  {i}. {f['feature']} ({strength(f['shap_value'])}) — {_feature_context(f['feature'], False)}.")
        if attack_features:
            na = len(attack_features)
            lines.append("")
            if top_overall is not None and top_overall["direction"] == "positive":
                lines.append(pick([
                    f"Interestingly, the single strongest measurement, {top_overall['feature']}, leaned "
                    f"towards attack. The decision was still normal because the model weighs all the features "
                    f"together rather than any one alone, and a split like this is exactly why two methods "
                    f"are compared.",
                    f"Notably, the most influential signal here, {top_overall['feature']}, pointed towards "
                    f"attack, yet the overall verdict was normal, as the model combines every feature rather "
                    f"than relying on the strongest.",
                ]))
            else:
                top_a = max(attack_features, key=lambda f: abs(f["shap_value"]))
                lines.append(pick([
                    f"A few signals were mildly unusual, most notably {top_a['feature']}, and {na} "
                    f"measurement{plur(na)} leaned towards attack, but none were strong enough to change the verdict.",
                    f"{na} measurement{plur(na)} leaned towards attack (the clearest being {top_a['feature']}), "
                    f"but none were decisive.",
                ]))
        lines += ["", pick([
            "In short, this behaves like ordinary, legitimate traffic, so it was allowed through without an alert.",
            "Overall, the connection looks like normal, legitimate activity and did not warrant an alert.",
            "Taken together, this resembles routine traffic and raised no alert.",
        ])]

    return "\n".join(lines)


def _remap_direction(direction: str) -> str:
    return "positive" if direction == "attack" else "negative"


def _sort_features(features: List[Dict], max_features: int = 8) -> List[Dict]:
    return sorted(features, key=lambda f: abs(f["shap_value"]), reverse=True)[:max_features]


def trim_features(items: List[Dict], key: str, eps: float = 0.005, keep_min: int = 6) -> List[Dict]:
    """Drop features whose contribution is negligible (would display as 0.00), but
    always keep at least keep_min so the panel never looks empty."""
    ranked = sorted(items, key=lambda f: abs(f.get(key, 0.0)), reverse=True)
    kept = [f for f in ranked if abs(f.get(key, 0.0)) >= eps]
    return kept if len(kept) >= keep_min else ranked[:min(keep_min, len(ranked))]


class ExplainerService:
    """
    Formats inline SHAP factors (stored on alerts at classification time) for /api/explain.
    Also lazily builds a full Explainer (SHAP+LIME) for on-demand alert explanations.
    """

    def __init__(self):
        self._explainer = None  # lazy

    def _get_explainer(self, model_service):
        """Build (or reuse) the full SHAP+LIME explainer with NPZ background data."""
        if self._explainer is not None:
            return self._explainer
        from pathlib import Path
        import numpy as np
        from src.explainer import Explainer

        base = Path(__file__).parent.parent.parent
        dataset = model_service.dataset or "2017"
        npz = base / "data" / "processed" / f"processed_data_{dataset}.npz"
        if not npz.exists():
            npz = base / "data" / "processed" / "processed_data.npz"
        if not npz.exists():
            raise RuntimeError("No processed data available — train or preprocess a dataset first.")

        bg = np.load(npz, allow_pickle=True)["X"][:100]
        ex = Explainer(model=model_service.model, feature_names=model_service.feature_names)
        ex.setup(bg)
        self._explainer = ex
        return ex

    def get_explainer(self, model_service):
        """Public accessor — build (or reuse) the full SHAP+LIME explainer."""
        return self._get_explainer(model_service)

    def reset(self):
        """Drop the cached explainer (call after model reload)."""
        self._explainer = None

    def explain(self, alert: Dict, model_service) -> Dict:
        features = None

        # Preferred path: if the full feature vector is stored, recompute SHAP so
        # we can show EVERY feature (not just the 3 stored inline at capture time).
        feats = alert.get("features")
        if feats:
            try:
                import numpy as np
                explainer = self._get_explainer(model_service)
                if explainer.shap_explainer:
                    X = np.array(feats, dtype=np.float32).reshape(1, -1)
                    result = explainer.explain(X, method="shap")
                    sx = result.get("shap_explanation") or {}
                    contribs = sx.get("all_contributions") or sx.get("contributions") or []
                    if contribs:
                        features = [
                            {
                                "feature":    c["feature"],
                                "shap_value": float(c["shap_value"]),
                                "direction":  _remap_direction(c.get("direction", "attack")),
                            }
                            for c in contribs
                        ]
            except Exception as e:
                logger.debug("Full SHAP recompute failed, will fall back to stored factors: %s", e)

        # Fallback: the 3 factors stored inline at capture time (attack flows).
        if features is None:
            shap_top3 = alert.get("shap_top3") or []
            if not shap_top3:
                raise RuntimeError(
                    "No feature vector or SHAP factors stored for this alert "
                    "(restart the monitor to capture alerts with full features)."
                )
            features = [
                {
                    "feature":    f["feature"],
                    "shap_value": float(f["value"]),
                    "direction":  _remap_direction(f.get("direction", "attack")),
                }
                for f in shap_top3
            ]

        # Show all features, ordered by importance (largest contribution first).
        features = _sort_features(features, max_features=len(features))

        prediction  = alert.get("prediction", "Unknown")
        attack_prob = float(alert.get("attack_prob", 0.0))
        narrative   = _build_shap_narrative(prediction, attack_prob, features)

        # If this is an attack and the raw feature vector is available, name the
        # attack type with the secondary multi-class classifier (a real prediction).
        predicted_type = None
        predicted_type_conf = None
        feats = alert.get("features")
        if feats and prediction.upper() == "ATTACK":
            try:
                import numpy as np
                from api.services.type_classifier_service import type_classifier_service
                ds = model_service.dataset or "2017"
                res = type_classifier_service.predict(
                    np.array(feats, dtype=np.float32).reshape(1, -1), ds)
                if res:
                    predicted_type = res["type"]
                    predicted_type_conf = round(res["confidence"], 4)
            except Exception as e:
                logger.debug("Type prediction unavailable: %s", e)

        return {
            "alert_id":    alert["id"],
            "prediction":  prediction,
            "attack_prob": attack_prob,
            "true_type":   alert.get("true_type"),
            "predicted_type": predicted_type,
            "predicted_type_conf": predicted_type_conf,
            "features":    trim_features(features, "shap_value"),
            "summary":     narrative,
        }

    def explain_lime(self, alert: Dict, model_service) -> Dict:
        """Run LIME against the alert's stored feature vector. ~5–10 seconds."""
        feats = alert.get("features")
        if not feats:
            raise RuntimeError(
                "No raw feature vector stored for this alert (alert predates LIME support — "
                "restart the monitor to capture new alerts with full features)."
            )

        import numpy as np
        explainer = self._get_explainer(model_service)
        if not explainer.lime_explainer:
            raise RuntimeError("LIME is not available (lime package not installed).")

        X = np.array(feats, dtype=np.float32).reshape(1, -1)
        result = explainer.explain(X, method="lime")

        lime_expl = result.get("lime_explanation") or {}
        contribs = lime_expl.get("contributions", [])

        rules = [
            {
                "feature":     c["feature"],
                "description": c.get("description", c["feature"]),
                "lime_weight": round(float(c["lime_weight"]), 4),
                "direction":   "positive" if c["direction"] == "attack" else "negative",
            }
            for c in contribs
        ]

        prediction  = alert.get("prediction", "Unknown")
        attack_prob = float(alert.get("attack_prob", 0.0))

        # Reuse the existing feature-context narrative engine for plain-English LIME copy
        narrative = _build_shap_narrative(prediction, attack_prob,
            [{"feature": r["feature"], "shap_value": r["lime_weight"], "direction": r["direction"]} for r in rules])

        return {
            "alert_id":    alert["id"],
            "prediction":  prediction,
            "attack_prob": attack_prob,
            "rules":       trim_features(rules, "lime_weight"),
            "summary":     narrative,
            "elapsed_seconds": round(float(lime_expl.get("time_seconds", 0)), 2),
        }


# Global singleton
explainer_service = ExplainerService()
