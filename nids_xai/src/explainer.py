"""
XAI Explainer for NIDS.
Supports both SHAP and LIME for comparison.

Author: Final Year CS Project
"""

import sys
from pathlib import Path
from typing import Optional, List, Dict, Tuple
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.config import SHAP_SAMPLE_SIZE, SHAP_MAX_DISPLAY, OUTPUT_DIR
from src.utils import (
    print_header, print_subheader, print_success, print_info, 
    print_warning, print_error, get_timestamp,
)

# Try importing XAI libraries
SHAP_AVAILABLE = False
LIME_AVAILABLE = False

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    pass

try:
    import lime
    import lime.lime_tabular
    LIME_AVAILABLE = True
except ImportError:
    pass


class Explainer:
    """
    XAI Explainer - Supports both SHAP and LIME.
    Allows side-by-side comparison of explanations.
    """
    
    def __init__(self, model, feature_names: List[str]):
        self.model = model
        self.feature_names = feature_names
        self.shap_explainer = None
        self.lime_explainer = None
        self.background_data = None
        self.is_ready = False
        
        # Feature descriptions
        self.feature_desc = {
            "Flow Duration": "connection duration",
            "Total Fwd Packets": "packets sent",
            "Total Backward Packets": "packets received",
            "Fwd Packet Length Max": "max packet size sent",
            "Fwd Packet Length Mean": "avg packet size sent",
            "Bwd Packet Length Max": "max packet size received",
            "Flow Bytes/s": "data transfer rate",
            "Flow Packets/s": "packet rate",
            "Flow IAT Mean": "avg time between packets",
            "SYN Flag Count": "connection attempts",
            "RST Flag Count": "connection resets",
            "PSH Flag Count": "push flags",
            "ACK Flag Count": "acknowledgments",
            "Init_Win_bytes_forward": "initial window size",
            "Destination Port": "target port",
        }
    
    def setup(self, X_background: np.ndarray) -> bool:
        """Setup both SHAP and LIME explainers."""
        print_info("Setting up XAI explainers...")
        
        # Sample background data
        if len(X_background) > SHAP_SAMPLE_SIZE:
            idx = np.random.choice(len(X_background), SHAP_SAMPLE_SIZE, replace=False)
            self.background_data = X_background[idx]
        else:
            self.background_data = X_background
        
        # Setup SHAP
        if SHAP_AVAILABLE:
            try:
                self.shap_explainer = shap.TreeExplainer(self.model)
                print_success("  SHAP explainer ready")
            except Exception as e:
                print_warning(f"  SHAP setup failed: {e}")
        else:
            print_warning("  SHAP not installed (pip install shap)")
        
        # Setup LIME
        if LIME_AVAILABLE:
            try:
                self.lime_explainer = lime.lime_tabular.LimeTabularExplainer(
                    training_data=self.background_data,
                    feature_names=self.feature_names,
                    class_names=['Benign', 'Attack'],
                    mode='classification',
                    discretize_continuous=True
                )
                print_success("  LIME explainer ready")
            except Exception as e:
                print_warning(f"  LIME setup failed: {e}")
        else:
            print_warning("  LIME not installed (pip install lime)")
        
        self.is_ready = (self.shap_explainer is not None) or (self.lime_explainer is not None)
        
        if self.is_ready:
            print_success("XAI ready!")
        else:
            print_error("No XAI methods available")
        
        return self.is_ready
    
    def explain(self, X: np.ndarray, true_label: Optional[int] = None,
                method: str = "both") -> Dict:
        """
        Generate explanation using SHAP, LIME, or both.
        method: "shap", "lime", or "both"
        """
        if X.ndim == 1:
            X = X.reshape(1, -1)
        
        # Get prediction
        prediction = int(self.model.predict(X)[0])
        proba = self.model.predict_proba(X)[0]
        confidence = float(proba[prediction])
        
        result = {
            "prediction": "ATTACK" if prediction == 1 else "BENIGN",
            "prediction_code": prediction,
            "confidence": confidence,
            "probabilities": {"Benign": float(proba[0]), "Attack": float(proba[1])},
            "correct": (true_label == prediction) if true_label is not None else None,
            "shap_explanation": None,
            "lime_explanation": None,
        }
        
        # SHAP explanation
        if method in ["shap", "both"] and self.shap_explainer:
            result["shap_explanation"] = self._get_shap_explanation(X)
        
        # LIME explanation
        if method in ["lime", "both"] and self.lime_explainer:
            result["lime_explanation"] = self._get_lime_explanation(X)
        
        return result
    
    def _get_shap_explanation(self, X: np.ndarray) -> Dict:
        """Get SHAP explanation."""
        try:
            import time
            start = time.time()
            
            shap_values = self.shap_explainer.shap_values(X)
            
            # Handle different output formats
            if isinstance(shap_values, list) and len(shap_values) == 2:
                sv = shap_values[1][0]  # Attack class
            elif isinstance(shap_values, np.ndarray):
                if shap_values.ndim == 3:
                    sv = shap_values[0, :, 1]
                else:
                    sv = shap_values[0]
            else:
                sv = np.zeros(len(self.feature_names))
            
            elapsed = time.time() - start
            
            # Create contributions list
            contributions = []
            for i, (name, val) in enumerate(zip(self.feature_names, sv)):
                feature_val = float(X[0, i]) if i < X.shape[1] else 0
                contributions.append({
                    "feature": name,
                    "shap_value": float(val),
                    "feature_value": feature_val,
                    "direction": "attack" if val > 0 else "benign"
                })
            
            # Sort by absolute SHAP value
            contributions.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
            
            return {
                "method": "SHAP",
                "time_seconds": elapsed,
                "contributions": contributions[:SHAP_MAX_DISPLAY],
                "all_contributions": contributions,
            }
            
        except Exception as e:
            return {"method": "SHAP", "error": str(e)}
    
    def _get_lime_explanation(self, X: np.ndarray) -> Dict:
        """Get LIME explanation."""
        try:
            import time
            start = time.time()
            
            exp = self.lime_explainer.explain_instance(
                data_row=X[0],
                predict_fn=self.model.predict_proba,
                num_features=len(self.feature_names)
            )
            
            elapsed = time.time() - start
            
            # Extract contributions
            contributions = []
            for feature_desc, weight in exp.as_list():
                # Parse feature name from LIME's format
                feature_name = feature_desc.split()[0] if feature_desc else "Unknown"
                
                # Find actual feature name
                for fn in self.feature_names:
                    if fn in feature_desc:
                        feature_name = fn
                        break
                
                contributions.append({
                    "feature": feature_name,
                    "description": feature_desc,
                    "lime_weight": float(weight),
                    "direction": "attack" if weight > 0 else "benign"
                })
            
            return {
                "method": "LIME",
                "time_seconds": elapsed,
                "contributions": contributions,
                "intercept": float(exp.intercept[1]) if hasattr(exp, 'intercept') else 0,
            }
            
        except Exception as e:
            return {"method": "LIME", "error": str(e)}
    
    def print_explanation(self, result: Dict) -> None:
        """Print formatted explanation - SHAP first, then LIME."""
        pred = result["prediction"]
        conf = result["confidence"] * 100
        
        print()
        print("=" * 70)
        print("                      PREDICTION EXPLANATION")
        print("=" * 70)
        print()
        
        # Main decision
        if result["prediction_code"] == 1:
            print(f"  🚨 DECISION: This network traffic is MALICIOUS (ATTACK)")
        else:
            print(f"  ✅ DECISION: This network traffic is NORMAL (BENIGN)")
        
        print(f"  📊 CONFIDENCE: {conf:.1f}%")
        
        # Correctness
        if result["correct"] is not None:
            if result["correct"]:
                print(f"  ✓  RESULT: Correct prediction")
            else:
                print(f"  ✗  RESULT: Incorrect prediction")
        
        print()
        
        # SHAP Explanation
        shap_exp = result.get("shap_explanation")
        if shap_exp and "error" not in shap_exp:
            self._print_shap_section(shap_exp, result["prediction_code"])
        elif shap_exp and "error" in shap_exp:
            print(f"  SHAP Error: {shap_exp.get('error')}")
        
        # LIME Explanation
        lime_exp = result.get("lime_explanation")
        if lime_exp and "error" not in lime_exp:
            self._print_lime_section(lime_exp, result["prediction_code"])
        elif lime_exp and "error" in lime_exp:
            print(f"  LIME Error: {lime_exp.get('error')}")
        
        print("=" * 70)
        print()
    
    def _print_shap_section(self, shap_exp: Dict, prediction: int):
        """Print SHAP explanation section with English summary."""
        print("-" * 70)
        print(f"  📊 SHAP EXPLANATION (Time: {shap_exp.get('time_seconds', 0):.3f}s)")
        print("-" * 70)
        print()
        print("  SHAP (SHapley Additive exPlanations) shows how each feature")
        print("  contributes to pushing the prediction toward Attack or Benign.")
        print()
        
        contribs = shap_exp.get("contributions", [])
        attack_factors = [c for c in contribs if c.get("shap_value", 0) > 0]
        benign_factors = [c for c in contribs if c.get("shap_value", 0) < 0]
        
        if prediction == 1:  # Attack
            print("  🚨 Features pushing toward ATTACK:")
            for c in attack_factors[:5]:
                val = c["shap_value"]
                feat_val = c.get("feature_value", 0)
                print(f"      • {c['feature'][:30]:<30} = {self._format_val(feat_val):<10} (SHAP: {val:+.4f})")
            
            if benign_factors:
                print()
                print("  ✓ Features pushing toward BENIGN (not enough to override):")
                for c in benign_factors[:3]:
                    val = c["shap_value"]
                    feat_val = c.get("feature_value", 0)
                    print(f"      • {c['feature'][:30]:<30} = {self._format_val(feat_val):<10} (SHAP: {val:+.4f})")
        else:  # Benign
            print("  ✓ Features pushing toward BENIGN:")
            for c in benign_factors[:5]:
                val = c["shap_value"]
                feat_val = c.get("feature_value", 0)
                print(f"      • {c['feature'][:30]:<30} = {self._format_val(feat_val):<10} (SHAP: {val:+.4f})")
            
            if attack_factors:
                print()
                print("  ⚠ Features pushing toward ATTACK (not enough to trigger):")
                for c in attack_factors[:3]:
                    val = c["shap_value"]
                    feat_val = c.get("feature_value", 0)
                    print(f"      • {c['feature'][:30]:<30} = {self._format_val(feat_val):<10} (SHAP: {val:+.4f})")
        
        # English summary
        print()
        print("  " + "-" * 50)
        print("  📝 SHAP Summary (Plain English):")
        print("  " + "-" * 50)
        summary = self._generate_shap_summary(attack_factors, benign_factors, prediction, contribs)
        for line in summary:
            print(f"  {line}")
        print()
    
    def _print_lime_section(self, lime_exp: Dict, prediction: int):
        """Print LIME explanation section with English summary."""
        print("-" * 70)
        print(f"  🍋 LIME EXPLANATION (Time: {lime_exp.get('time_seconds', 0):.3f}s)")
        print("-" * 70)
        print()
        print("  LIME (Local Interpretable Model-agnostic Explanations) creates")
        print("  a simple local model to explain this specific prediction.")
        print()
        
        contribs = lime_exp.get("contributions", [])
        attack_factors = [c for c in contribs if c.get("lime_weight", 0) > 0]
        benign_factors = [c for c in contribs if c.get("lime_weight", 0) < 0]
        
        if prediction == 1:  # Attack
            print("  🚨 Rules indicating ATTACK:")
            for c in attack_factors[:5]:
                weight = c["lime_weight"]
                desc = c.get("description", c["feature"])
                print(f"      • {desc[:45]:<45} (weight: {weight:+.4f})")
            
            if benign_factors:
                print()
                print("  ✓ Rules indicating BENIGN:")
                for c in benign_factors[:3]:
                    weight = c["lime_weight"]
                    desc = c.get("description", c["feature"])
                    print(f"      • {desc[:45]:<45} (weight: {weight:+.4f})")
        else:  # Benign
            print("  ✓ Rules indicating BENIGN:")
            for c in benign_factors[:5]:
                weight = c["lime_weight"]
                desc = c.get("description", c["feature"])
                print(f"      • {desc[:45]:<45} (weight: {weight:+.4f})")
            
            if attack_factors:
                print()
                print("  ⚠ Rules indicating ATTACK:")
                for c in attack_factors[:3]:
                    weight = c["lime_weight"]
                    desc = c.get("description", c["feature"])
                    print(f"      • {desc[:45]:<45} (weight: {weight:+.4f})")
        
        # English summary
        print()
        print("  " + "-" * 50)
        print("  📝 LIME Summary (Plain English):")
        print("  " + "-" * 50)
        summary = self._generate_lime_summary(attack_factors, benign_factors, prediction, contribs)
        for line in summary:
            print(f"  {line}")
        print()
    
    def _format_val(self, value: float) -> str:
        """Format value for display."""
        if abs(value) >= 1000000:
            return f"{value/1000000:.1f}M"
        elif abs(value) >= 1000:
            return f"{value/1000:.1f}K"
        elif abs(value) < 0.01 and value != 0:
            return f"{value:.4f}"
        else:
            return f"{value:.2f}"
    
    def _get_feature_description(self, feature_name: str) -> str:
        """Get human-readable description of a feature."""
        descriptions = {
            "Flow Duration": "the connection lasted",
            "Total Fwd Packets": "packets were sent",
            "Total Backward Packets": "packets were received",
            "Total Length of Fwd Packets": "bytes were sent",
            "Total Length of Bwd Packets": "bytes were received",
            "Fwd Packet Length Max": "the largest sent packet was",
            "Fwd Packet Length Mean": "the average sent packet size was",
            "Bwd Packet Length Max": "the largest received packet was",
            "Bwd Packet Length Mean": "the average received packet size was",
            "Flow Bytes/s": "the data transfer rate was",
            "Flow Packets/s": "packets per second were",
            "Flow IAT Mean": "the average time between packets was",
            "Flow IAT Max": "the maximum gap between packets was",
            "Fwd IAT Total": "total forward inter-arrival time was",
            "Bwd IAT Total": "total backward inter-arrival time was",
            "Fwd PSH Flags": "push flags (urgent data) were",
            "SYN Flag Count": "connection initiation attempts (SYN flags) were",
            "RST Flag Count": "connection resets were",
            "ACK Flag Count": "acknowledgments were",
            "PSH Flag Count": "push flags were",
            "FIN Flag Count": "connection terminations were",
            "Init_Win_bytes_forward": "the initial TCP window size was",
            "Init_Win_bytes_backward": "the response window size was",
            "Destination Port": "the target port was",
            "Fwd Packets/s": "outgoing packets per second were",
            "Bwd Packets/s": "incoming packets per second were",
            "Packet Length Variance": "packet size variation was",
            "Average Packet Size": "the average packet size was",
            "Subflow Fwd Bytes": "forward subflow bytes were",
            "Subflow Bwd Bytes": "backward subflow bytes were",
        }
        
        # Check exact match
        if feature_name in descriptions:
            return descriptions[feature_name]
        
        # Check partial match
        for key, desc in descriptions.items():
            if key.lower() in feature_name.lower():
                return desc
        
        return f"{feature_name} was"
    
    def _generate_shap_summary(self, attack_factors: List, benign_factors: List, 
                                prediction: int, all_contribs: List) -> List[str]:
        """Generate plain English summary for SHAP explanation."""
        lines = []
        
        if prediction == 1:  # Attack detected
            lines.append("")
            lines.append("The model flagged this as an ATTACK because:")
            lines.append("")
            
            # Top 3 attack reasons
            for i, c in enumerate(attack_factors[:3], 1):
                feat = c["feature"]
                val = c.get("feature_value", 0)
                desc = self._get_feature_description(feat)
                
                # Generate contextual explanation
                if "SYN" in feat:
                    lines.append(f"  {i}. High number of SYN flags ({self._format_val(val)}) suggests")
                    lines.append(f"     a port scan or SYN flood attack pattern.")
                elif "Duration" in feat and val < 1:
                    lines.append(f"  {i}. Very short connection duration ({self._format_val(val)}s) is typical")
                    lines.append(f"     of automated scanning or attack tools.")
                elif "Packets/s" in feat and val > 100:
                    lines.append(f"  {i}. Unusually high packet rate ({self._format_val(val)}/s) indicates")
                    lines.append(f"     possible flooding or rapid probing behavior.")
                elif "Port" in feat:
                    lines.append(f"  {i}. The targeted port ({int(val)}) combined with other factors")
                    lines.append(f"     suggests malicious intent.")
                elif "RST" in feat:
                    lines.append(f"  {i}. Multiple connection resets ({self._format_val(val)}) suggest")
                    lines.append(f"     port scanning or failed attack attempts.")
                else:
                    lines.append(f"  {i}. The value of {feat} ({self._format_val(val)})")
                    lines.append(f"     is abnormal compared to legitimate traffic.")
            
            if benign_factors:
                lines.append("")
                lines.append(f"  Note: {len(benign_factors)} feature(s) showed normal behavior,")
                lines.append(f"  but the suspicious indicators were stronger.")
        
        else:  # Benign
            lines.append("")
            lines.append("The model classified this as NORMAL because:")
            lines.append("")
            
            for i, c in enumerate(benign_factors[:3], 1):
                feat = c["feature"]
                val = c.get("feature_value", 0)
                
                if "Duration" in feat:
                    lines.append(f"  {i}. Connection duration ({self._format_val(val)}s) is consistent")
                    lines.append(f"     with normal user/application behavior.")
                elif "Packet" in feat and "Length" in feat:
                    lines.append(f"  {i}. Packet sizes ({self._format_val(val)}) are within normal range")
                    lines.append(f"     for legitimate network traffic.")
                elif "Bytes/s" in feat:
                    lines.append(f"  {i}. Data transfer rate ({self._format_val(val)}/s) matches")
                    lines.append(f"     expected patterns for normal usage.")
                else:
                    lines.append(f"  {i}. The {feat} value ({self._format_val(val)})")
                    lines.append(f"     falls within the normal range.")
            
            if attack_factors:
                lines.append("")
                lines.append(f"  Note: {len(attack_factors)} feature(s) were slightly unusual,")
                lines.append(f"  but not significant enough to indicate an attack.")
        
        lines.append("")
        return lines
    
    def _generate_lime_summary(self, attack_factors: List, benign_factors: List,
                                prediction: int, all_contribs: List) -> List[str]:
        """Generate plain English summary for LIME explanation."""
        lines = []
        
        if prediction == 1:  # Attack
            lines.append("")
            lines.append("LIME identified these key rules for the ATTACK decision:")
            lines.append("")
            
            for i, c in enumerate(attack_factors[:3], 1):
                desc = c.get("description", c["feature"])
                weight = c["lime_weight"]
                
                # Parse the rule to make it more readable
                if "<=" in desc:
                    parts = desc.split("<=")
                    feat = parts[0].strip()
                    threshold = parts[1].strip() if len(parts) > 1 else "threshold"
                    lines.append(f"  {i}. When {feat} is low (≤ {threshold}),")
                    lines.append(f"     it strongly suggests attack behavior (weight: {weight:+.3f})")
                elif ">" in desc:
                    parts = desc.split(">")
                    feat = parts[0].strip()
                    threshold = parts[1].strip() if len(parts) > 1 else "threshold"
                    lines.append(f"  {i}. When {feat} is high (> {threshold}),")
                    lines.append(f"     it indicates potential attack (weight: {weight:+.3f})")
                else:
                    lines.append(f"  {i}. Rule: {desc}")
                    lines.append(f"     contributes to attack detection (weight: {weight:+.3f})")
            
            lines.append("")
            lines.append("  In simple terms: The combination of these conditions")
            lines.append("  matches patterns commonly seen in network attacks.")
        
        else:  # Benign
            lines.append("")
            lines.append("LIME identified these key rules for the BENIGN decision:")
            lines.append("")
            
            for i, c in enumerate(benign_factors[:3], 1):
                desc = c.get("description", c["feature"])
                weight = c["lime_weight"]
                
                if "<=" in desc:
                    parts = desc.split("<=")
                    feat = parts[0].strip()
                    threshold = parts[1].strip() if len(parts) > 1 else "threshold"
                    lines.append(f"  {i}. When {feat} is moderate (≤ {threshold}),")
                    lines.append(f"     it suggests normal traffic (weight: {weight:+.3f})")
                elif ">" in desc:
                    parts = desc.split(">")
                    feat = parts[0].strip()
                    threshold = parts[1].strip() if len(parts) > 1 else "threshold"
                    lines.append(f"  {i}. When {feat} is above {threshold},")
                    lines.append(f"     it's consistent with legitimate use (weight: {weight:+.3f})")
                else:
                    lines.append(f"  {i}. Rule: {desc}")
                    lines.append(f"     indicates normal behavior (weight: {weight:+.3f})")
            
            lines.append("")
            lines.append("  In simple terms: This traffic follows patterns that are")
            lines.append("  typical of normal, legitimate network activity.")
        
        lines.append("")
        return lines
    
    def explain_batch(self, X: np.ndarray, y_true: Optional[np.ndarray] = None,
                      n_samples: int = 3, method: str = "both") -> List[Dict]:
        """Explain multiple samples."""
        results = []
        n = min(n_samples, len(X))
        
        # Get mix of predictions
        predictions = self.model.predict(X)
        attack_idx = np.where(predictions == 1)[0]
        benign_idx = np.where(predictions == 0)[0]
        
        indices = []
        if len(attack_idx) > 0:
            indices.extend(np.random.choice(attack_idx, min(2, len(attack_idx)), replace=False))
        if len(benign_idx) > 0 and len(indices) < n:
            indices.extend(np.random.choice(benign_idx, min(n - len(indices), len(benign_idx)), replace=False))
        
        for i, idx in enumerate(indices[:n]):
            print(f"\n{'='*70}")
            print(f"  SAMPLE {i+1} (Index: {idx})")
            print(f"{'='*70}")
            
            true_label = int(y_true[idx]) if y_true is not None else None
            result = self.explain(X[idx], true_label, method=method)
            self.print_explanation(result)
            results.append(result)
        
        return results
    
    def get_global_importance(self, X: np.ndarray, save_plot: bool = True) -> Dict:
        """Get and visualize global feature importance."""
        print_header("Global Feature Importance")
        
        # Use model's feature importances
        importances = self.model.feature_importances_
        
        # Rank features
        importance_list = list(zip(self.feature_names, importances))
        importance_list.sort(key=lambda x: x[1], reverse=True)
        
        # ASCII visualization
        print_subheader("Top 15 Most Important Features")
        print()
        
        max_imp = importance_list[0][1] if importance_list else 1
        
        for i, (name, imp) in enumerate(importance_list[:15], 1):
            bar_width = int((imp / max_imp) * 30)
            bar = "█" * bar_width + "░" * (30 - bar_width)
            pct = imp * 100
            print(f"  {i:2d}. {name[:25]:<25} │{bar}│ {pct:5.2f}%")
        
        # Save plot if matplotlib available
        if save_plot:
            self._save_importance_plot(importance_list[:15])
        
        return {"importance": importance_list}
    
    def _save_importance_plot(self, importance_list: List[Tuple]):
        """Save feature importance plot."""
        try:
            import matplotlib
            matplotlib.use('Agg')  # Non-interactive backend
            import matplotlib.pyplot as plt
            
            features = [x[0][:20] for x in importance_list]
            values = [x[1] for x in importance_list]
            
            fig, ax = plt.subplots(figsize=(10, 6))
            bars = ax.barh(range(len(features)), values, color='steelblue')
            ax.set_yticks(range(len(features)))
            ax.set_yticklabels(features)
            ax.invert_yaxis()
            ax.set_xlabel('Importance')
            ax.set_title('Top 15 Feature Importance (Random Forest)')
            
            # Add value labels
            for bar, val in zip(bars, values):
                ax.text(val + 0.001, bar.get_y() + bar.get_height()/2,
                       f'{val:.3f}', va='center', fontsize=8)
            
            plt.tight_layout()
            
            filepath = OUTPUT_DIR / f"feature_importance_{get_timestamp().replace(':', '-').replace(' ', '_')}.png"
            plt.savefig(filepath, dpi=150, bbox_inches='tight')
            plt.close()
            
            print_success(f"\n  Plot saved: {filepath}")
            
        except ImportError:
            print_warning("\n  Matplotlib not available for plotting")
        except Exception as e:
            print_warning(f"\n  Could not save plot: {e}")
    
    def compare_methods_timing(self, X: np.ndarray, n_samples: int = 10) -> Dict:
        """Compare SHAP vs LIME timing."""
        print_header("SHAP vs LIME Performance Comparison")
        
        if not SHAP_AVAILABLE or not LIME_AVAILABLE:
            print_error("Both SHAP and LIME required for comparison")
            return {}
        
        import time
        
        n = min(n_samples, len(X))
        indices = np.random.choice(len(X), n, replace=False)
        
        shap_times = []
        lime_times = []
        
        print_info(f"Testing on {n} samples...")
        print()
        
        for i, idx in enumerate(indices):
            # SHAP timing
            start = time.time()
            self.shap_explainer.shap_values(X[idx:idx+1])
            shap_times.append(time.time() - start)
            
            # LIME timing
            start = time.time()
            self.lime_explainer.explain_instance(
                X[idx], self.model.predict_proba, num_features=10
            )
            lime_times.append(time.time() - start)
            
            print(f"  Sample {i+1}: SHAP={shap_times[-1]:.3f}s, LIME={lime_times[-1]:.3f}s")
        
        # Summary
        print()
        print("-" * 50)
        print("  Summary:")
        print(f"  {'Method':<10} {'Avg Time':<12} {'Min':<10} {'Max':<10}")
        print("-" * 50)
        print(f"  {'SHAP':<10} {np.mean(shap_times):.4f}s     {min(shap_times):.4f}s   {max(shap_times):.4f}s")
        print(f"  {'LIME':<10} {np.mean(lime_times):.4f}s     {min(lime_times):.4f}s   {max(lime_times):.4f}s")
        print("-" * 50)
        
        faster = "SHAP" if np.mean(shap_times) < np.mean(lime_times) else "LIME"
        ratio = max(np.mean(shap_times), np.mean(lime_times)) / min(np.mean(shap_times), np.mean(lime_times))
        print(f"\n  {faster} is {ratio:.1f}x faster on average")
        
        return {
            "shap_times": shap_times,
            "lime_times": lime_times,
            "shap_avg": np.mean(shap_times),
            "lime_avg": np.mean(lime_times),
        }
