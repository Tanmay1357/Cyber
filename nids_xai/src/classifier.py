"""
Classifier for NIDS with XAI.
Classifies new data with automatic explanations.

Author: Final Year CS Project
"""

import sys
from pathlib import Path
from typing import Optional, Dict
import pandas as pd
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.config import OUTPUT_DIR, AUTO_EXPLAIN
from src.utils import (
    print_header, print_subheader, print_success, print_error,
    print_info, print_warning, format_number, get_timestamp,
)


class Classifier:
    """Classify new data with explanations."""
    
    def __init__(self, model, preprocessor, explainer=None):
        self.model = model
        self.preprocessor = preprocessor
        self.explainer = explainer
    
    def classify_csv(self, filepath: str, explain: bool = AUTO_EXPLAIN) -> Dict:
        """Classify samples from CSV file."""
        print_header("Classifying New Data")
        
        path = Path(filepath)
        if not path.exists():
            print_error(f"File not found: {filepath}")
            return {"success": False}
        
        try:
            # Load
            print_info(f"Loading: {path.name}")
            data = pd.read_csv(filepath, low_memory=False)
            print_info(f"Loaded {format_number(len(data))} samples")
            
            # Preprocess
            print_info("Preprocessing...")
            X = self.preprocessor.transform(data)
            
            # Predict
            print_info("Classifying...")
            predictions = self.model.predict(X)
            probabilities = self.model.predict_proba(X)
            
            # Summary
            results = self._summarize(predictions, probabilities)
            results["success"] = True
            results["filepath"] = str(path)
            
            self._display(results)
            
            # Auto explain first few samples
            if explain and self.explainer and self.explainer.is_ready:
                self._explain_samples(X, predictions, probabilities)
            
            return results
            
        except Exception as e:
            print_error(f"Classification failed: {e}")
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    def classify_single(self, sample: np.ndarray, explain: bool = True) -> Dict:
        """Classify a single sample with explanation."""
        if sample.ndim == 1:
            sample = sample.reshape(1, -1)
        
        prediction = self.model.predict(sample)[0]
        proba = self.model.predict_proba(sample)[0]
        
        result = {
            "prediction": "Attack" if prediction == 1 else "Benign",
            "confidence": float(proba[prediction]),
            "probabilities": {"Benign": float(proba[0]), "Attack": float(proba[1])},
        }
        
        # Explain
        if explain and self.explainer and self.explainer.is_ready:
            explanation = self.explainer.explain(sample)
            result["explanation"] = explanation
            self.explainer.print_explanation(explanation)
        
        return result
    
    def _summarize(self, predictions: np.ndarray, probabilities: np.ndarray) -> Dict:
        """Summarize results."""
        benign = (predictions == 0).sum()
        attack = (predictions == 1).sum()
        total = len(predictions)
        
        return {
            "total": total,
            "benign": int(benign),
            "attack": int(attack),
            "benign_pct": benign / total * 100,
            "attack_pct": attack / total * 100,
            "avg_confidence": float(probabilities.max(axis=1).mean()),
            "predictions": predictions,
            "probabilities": probabilities,
        }
    
    def _display(self, results: Dict) -> None:
        """Display results."""
        print_subheader("Classification Results")
        
        total = results["total"]
        benign = results["benign"]
        attack = results["attack"]
        
        # Bars
        benign_bar = "█" * int(results["benign_pct"] / 100 * 30)
        attack_bar = "█" * int(results["attack_pct"] / 100 * 30)
        
        print()
        print(f"  Benign (Normal): {benign:>8} ({results['benign_pct']:5.1f}%) {benign_bar}")
        print(f"  Attack:          {attack:>8} ({results['attack_pct']:5.1f}%) {attack_bar}")
        print(f"  Total:           {total:>8}")
        print()
        print(f"  Average Confidence: {results['avg_confidence']*100:.1f}%")
        
        if attack > 0:
            print_warning(f"\n⚠ WARNING: {attack} potential attacks detected!")
    
    def _explain_samples(self, X: np.ndarray, predictions: np.ndarray, 
                         probabilities: np.ndarray, n: int = 3) -> None:
        """Explain some sample predictions."""
        print_subheader("Sample Explanations")
        
        # Try to get one benign and some attacks
        attack_idx = np.where(predictions == 1)[0]
        benign_idx = np.where(predictions == 0)[0]
        
        samples_to_explain = []
        
        # Add attacks if any
        if len(attack_idx) > 0:
            n_attacks = min(2, len(attack_idx))
            samples_to_explain.extend(np.random.choice(attack_idx, n_attacks, replace=False))
        
        # Add benign if any
        if len(benign_idx) > 0 and len(samples_to_explain) < n:
            samples_to_explain.append(np.random.choice(benign_idx, 1)[0])
        
        for i, idx in enumerate(samples_to_explain):
            print(f"\n--- Explaining Sample {idx} ---")
            result = self.explainer.explain(X[idx])
            self.explainer.print_explanation(result)
    
    def save_results(self, results: Dict, filename: Optional[str] = None) -> str:
        """Save classification results."""
        if not filename:
            filename = f"classification_{get_timestamp().replace(':', '-').replace(' ', '_')}.csv"
        
        filepath = OUTPUT_DIR / filename
        
        df = pd.DataFrame({
            "prediction": results["predictions"],
            "label": ["Benign" if p == 0 else "Attack" for p in results["predictions"]],
            "confidence": results["probabilities"].max(axis=1),
            "prob_benign": results["probabilities"][:, 0],
            "prob_attack": results["probabilities"][:, 1],
        })
        
        df.to_csv(filepath, index=False)
        print_success(f"Results saved: {filepath}")
        
        return str(filepath)
