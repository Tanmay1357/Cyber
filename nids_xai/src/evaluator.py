"""
Model Evaluator for NIDS with XAI.
Includes ASCII and matplotlib visualizations.

Author: Final Year CS Project
"""

import sys
from pathlib import Path
from typing import Dict, Optional, List
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc, roc_auc_score
)

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.config import OUTPUT_DIR
from src.utils import (
    print_header, print_subheader, print_success,
    print_info, print_warning, get_timestamp, format_number,
)


class Evaluator:
    """Evaluate model with visual metrics."""
    
    def __init__(self):
        self.results = {}
    
    def evaluate(self, y_true: np.ndarray, y_pred: np.ndarray,
                 y_proba: Optional[np.ndarray] = None,
                 y_types: Optional[np.ndarray] = None,
                 attack_type_names: Optional[List[str]] = None,
                 save_plots: bool = True) -> Dict:
        """Full evaluation with visualizations."""
        print_header("Model Evaluation")
        
        # Core metrics
        self.results = {
            "accuracy": accuracy_score(y_true, y_pred),
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0),
            "f1": f1_score(y_true, y_pred, zero_division=0),
        }
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        self.results["confusion_matrix"] = cm
        
        if len(cm) == 2:
            tn, fp, fn, tp = cm.ravel()
            self.results["tp"] = int(tp)
            self.results["tn"] = int(tn)
            self.results["fp"] = int(fp)
            self.results["fn"] = int(fn)
            self.results["specificity"] = tn / (tn + fp) if (tn + fp) > 0 else 0
            self.results["fpr"] = fp / (fp + tn) if (fp + tn) > 0 else 0  # False Positive Rate
            self.results["fnr"] = fn / (fn + tp) if (fn + tp) > 0 else 0  # False Negative Rate
        
        # ROC-AUC
        if y_proba is not None:
            try:
                proba = y_proba[:, 1] if y_proba.ndim > 1 else y_proba
                self.results["roc_auc"] = roc_auc_score(y_true, proba)
                self.results["fpr_curve"], self.results["tpr_curve"], _ = roc_curve(y_true, proba)
            except:
                pass
        
        # Display metrics
        self._display_metrics_visual()
        self._display_confusion_matrix_visual(cm)
        
        # Per-attack-type accuracy
        if y_types is not None and attack_type_names:
            self._display_attack_type_breakdown(y_true, y_pred, y_types, attack_type_names)
        
        # Save plots
        if save_plots:
            self._save_all_plots(y_true, y_pred, y_proba, y_types, attack_type_names)
        
        return self.results
    
    def _display_metrics_visual(self):
        """Display metrics with visual bars."""
        print_subheader("Performance Metrics")
        print()
        
        metrics = [
            ("Accuracy", self.results["accuracy"]),
            ("Precision", self.results["precision"]),
            ("Recall (Detection Rate)", self.results["recall"]),
            ("F1-Score", self.results["f1"]),
        ]
        
        if "specificity" in self.results:
            metrics.append(("Specificity", self.results["specificity"]))
        if "roc_auc" in self.results:
            metrics.append(("ROC-AUC", self.results["roc_auc"]))
        
        max_name = max(len(m[0]) for m in metrics)
        
        for name, value in metrics:
            pct = value * 100
            bar_width = 30
            filled = int(value * bar_width)
            
            if pct >= 90:
                bar_char = "█"
            elif pct >= 70:
                bar_char = "▓"
            else:
                bar_char = "░"
            
            bar = bar_char * filled + "·" * (bar_width - filled)
            print(f"  {name:<{max_name}} │{bar}│ {pct:5.1f}%")
        
        print()
    
    def _display_confusion_matrix_visual(self, cm: np.ndarray):
        """Display confusion matrix."""
        print_subheader("Confusion Matrix")
        print()
        
        if len(cm) != 2:
            return
        
        tn, fp, fn, tp = cm.ravel()
        total = tn + fp + fn + tp
        
        tn_pct = tn / total * 100
        fp_pct = fp / total * 100
        fn_pct = fn / total * 100
        tp_pct = tp / total * 100
        
        print("                      ┌─────────────────────────────────┐")
        print("                      │         PREDICTED               │")
        print("                      │    Benign    │    Attack        │")
        print("  ┌───────────────────┼──────────────┼──────────────────┤")
        print(f"  │ ACTUAL   Benign   │  TN: {tn:>6}  │  FP: {fp:>6}      │")
        print(f"  │                   │   ({tn_pct:4.1f}%)   │   ({fp_pct:4.1f}%)       │")
        print("  │          ─────────┼──────────────┼──────────────────┤")
        print(f"  │          Attack   │  FN: {fn:>6}  │  TP: {tp:>6}      │")
        print(f"  │                   │   ({fn_pct:4.1f}%)   │   ({tp_pct:4.1f}%)       │")
        print("  └───────────────────┴──────────────┴──────────────────┘")
        print()
        
        # Interpretation
        print("  Interpretation:")
        print(f"    ✓ True Positives  (Attacks caught):    {tp:>7} ({tp_pct:5.1f}%)")
        print(f"    ✓ True Negatives  (Normal correct):    {tn:>7} ({tn_pct:5.1f}%)")
        print(f"    ✗ False Positives (False alarms):      {fp:>7} ({fp_pct:5.1f}%)")
        print(f"    ✗ False Negatives (Missed attacks):    {fn:>7} ({fn_pct:5.1f}%)")
        print()
        
        # Overall bar
        correct = tp + tn
        correct_pct = correct / total * 100
        bar_width = 40
        correct_bar = int(correct_pct / 100 * bar_width)
        
        print("  Overall Accuracy:")
        print(f"  ┌{'─' * bar_width}┐")
        print(f"  │{'█' * correct_bar}{'░' * (bar_width - correct_bar)}│")
        print(f"  └{'─' * bar_width}┘")
        print(f"   Correct: {correct_pct:.1f}%   Errors: {100 - correct_pct:.1f}%")
        print()
    
    def _display_attack_type_breakdown(self, y_true: np.ndarray, y_pred: np.ndarray,
                                       y_types: np.ndarray, attack_type_names: List[str]):
        """Show detection by attack type."""
        print_subheader("Detection by Attack Type")
        print()

        # Report samples with unknown attack type (index -1).
        # This happens in cross-dataset evaluation when the test set
        # contains attack labels not seen during training.
        unknown_mask = y_types == -1
        unknown_count = int(unknown_mask.sum())
        if unknown_count > 0:
            total_samples = len(y_types)
            unknown_pct = unknown_count / total_samples * 100
            print_warning(
                f"  {unknown_count:,} samples ({unknown_pct:.1f}%) have unknown attack types "
                f"(not seen during training) - excluded from per-type breakdown"
            )
            print()

        type_stats = []

        for i, attack_name in enumerate(attack_type_names):
            mask = y_types == i
            if mask.sum() == 0:
                continue

            total = mask.sum()

            if attack_name.upper() == "BENIGN":
                correct = ((y_pred == 0) & mask).sum()
            else:
                correct = ((y_pred == 1) & mask).sum()

            accuracy = correct / total if total > 0 else 0
            type_stats.append((attack_name, correct, total, accuracy))

        type_stats.sort(key=lambda x: x[2], reverse=True)

        max_name = max(len(s[0]) for s in type_stats) if type_stats else 10

        for name, correct, total, acc in type_stats[:10]:
            pct = acc * 100
            bar_width = 20
            filled = int(acc * bar_width)

            if pct >= 90:
                bar = "█" * filled + "·" * (bar_width - filled)
            elif pct >= 70:
                bar = "▓" * filled + "·" * (bar_width - filled)
            else:
                bar = "░" * filled + "·" * (bar_width - filled)

            print(f"  {name:<{max_name}} │ {correct:>6}/{total:<6} │{bar}│ {pct:5.1f}%")

        if len(type_stats) > 10:
            print(f"  ... and {len(type_stats) - 10} more types")
        print()
    
    def _save_all_plots(self, y_true, y_pred, y_proba, y_types, attack_type_names):
        """Save all visualization plots."""
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            
            timestamp = get_timestamp().replace(':', '-').replace(' ', '_')
            
            # 1. Confusion Matrix Plot
            self._save_confusion_matrix_plot(plt, timestamp)
            
            # 2. ROC Curve
            if y_proba is not None and "roc_auc" in self.results:
                self._save_roc_curve(plt, timestamp)
            
            # 3. Metrics Bar Chart
            self._save_metrics_bar(plt, timestamp)
            
            # 4. Attack Type Breakdown
            if y_types is not None and attack_type_names:
                self._save_attack_breakdown(plt, y_true, y_pred, y_types, 
                                           attack_type_names, timestamp)
            
        except ImportError:
            print_warning("  Matplotlib not available for saving plots")
        except Exception as e:
            print_warning(f"  Error saving plots: {e}")
    
    def _save_confusion_matrix_plot(self, plt, timestamp):
        """Save confusion matrix as image."""
        cm = self.results["confusion_matrix"]
        
        fig, ax = plt.subplots(figsize=(8, 6))
        im = ax.imshow(cm, cmap='Blues')
        
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(['Benign', 'Attack'])
        ax.set_yticklabels(['Benign', 'Attack'])
        ax.set_xlabel('Predicted')
        ax.set_ylabel('Actual')
        ax.set_title('Confusion Matrix')
        
        # Add text
        for i in range(2):
            for j in range(2):
                text = ax.text(j, i, f'{cm[i, j]:,}',
                              ha='center', va='center', fontsize=14,
                              color='white' if cm[i, j] > cm.max()/2 else 'black')
        
        plt.colorbar(im)
        plt.tight_layout()
        
        filepath = OUTPUT_DIR / f"confusion_matrix_{timestamp}.png"
        plt.savefig(filepath, dpi=150, bbox_inches='tight')
        plt.close()
        print_success(f"  Saved: {filepath.name}")
    
    def _save_roc_curve(self, plt, timestamp):
        """Save ROC curve."""
        fpr = self.results["fpr_curve"]
        tpr = self.results["tpr_curve"]
        roc_auc = self.results["roc_auc"]
        
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.plot(fpr, tpr, color='darkorange', lw=2, 
                label=f'ROC curve (AUC = {roc_auc:.3f})')
        ax.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random')
        ax.set_xlim([0.0, 1.0])
        ax.set_ylim([0.0, 1.05])
        ax.set_xlabel('False Positive Rate')
        ax.set_ylabel('True Positive Rate')
        ax.set_title('ROC Curve - Attack Detection')
        ax.legend(loc='lower right')
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        filepath = OUTPUT_DIR / f"roc_curve_{timestamp}.png"
        plt.savefig(filepath, dpi=150, bbox_inches='tight')
        plt.close()
        print_success(f"  Saved: {filepath.name}")
    
    def _save_metrics_bar(self, plt, timestamp):
        """Save metrics bar chart."""
        metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        values = [
            self.results["accuracy"],
            self.results["precision"],
            self.results["recall"],
            self.results["f1"]
        ]
        
        if "specificity" in self.results:
            metrics.append('Specificity')
            values.append(self.results["specificity"])
        
        if "roc_auc" in self.results:
            metrics.append('ROC-AUC')
            values.append(self.results["roc_auc"])
        
        fig, ax = plt.subplots(figsize=(10, 5))
        bars = ax.bar(metrics, [v * 100 for v in values], color='steelblue')
        
        ax.set_ylim(0, 105)
        ax.set_ylabel('Percentage (%)')
        ax.set_title('Model Performance Metrics')
        ax.axhline(y=90, color='green', linestyle='--', alpha=0.5, label='90% threshold')
        
        # Add value labels
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                   f'{val*100:.1f}%', ha='center', va='bottom', fontsize=10)
        
        plt.tight_layout()
        
        filepath = OUTPUT_DIR / f"metrics_{timestamp}.png"
        plt.savefig(filepath, dpi=150, bbox_inches='tight')
        plt.close()
        print_success(f"  Saved: {filepath.name}")
    
    def _save_attack_breakdown(self, plt, y_true, y_pred, y_types, 
                               attack_type_names, timestamp):
        """Save attack type breakdown."""
        type_stats = []
        
        for i, name in enumerate(attack_type_names):
            mask = y_types == i
            if mask.sum() == 0:
                continue
            
            total = mask.sum()
            if name.upper() == "BENIGN":
                correct = ((y_pred == 0) & mask).sum()
            else:
                correct = ((y_pred == 1) & mask).sum()
            
            acc = correct / total if total > 0 else 0
            type_stats.append((name[:20], acc, total))
        
        type_stats.sort(key=lambda x: x[2], reverse=True)
        type_stats = type_stats[:10]
        
        names = [x[0] for x in type_stats]
        accs = [x[1] * 100 for x in type_stats]
        counts = [x[2] for x in type_stats]
        
        fig, ax = plt.subplots(figsize=(12, 6))
        bars = ax.barh(range(len(names)), accs, color='steelblue')
        ax.set_yticks(range(len(names)))
        ax.set_yticklabels([f"{n} ({c:,})" for n, c in zip(names, counts)])
        ax.invert_yaxis()
        ax.set_xlabel('Detection Accuracy (%)')
        ax.set_title('Detection Accuracy by Attack Type')
        ax.axvline(x=90, color='green', linestyle='--', alpha=0.5)
        ax.set_xlim(0, 105)
        
        for bar, acc in zip(bars, accs):
            ax.text(acc + 1, bar.get_y() + bar.get_height()/2,
                   f'{acc:.1f}%', va='center', fontsize=9)
        
        plt.tight_layout()
        
        filepath = OUTPUT_DIR / f"attack_breakdown_{timestamp}.png"
        plt.savefig(filepath, dpi=150, bbox_inches='tight')
        plt.close()
        print_success(f"  Saved: {filepath.name}")
    
    def save_report(self, filename: Optional[str] = None) -> str:
        """Save text report."""
        if not filename:
            filename = f"evaluation_{get_timestamp().replace(':', '-').replace(' ', '_')}.txt"
        
        filepath = OUTPUT_DIR / filename
        
        with open(filepath, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("NIDS Model Evaluation Report\n")
            f.write(f"Generated: {get_timestamp()}\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("PERFORMANCE METRICS\n")
            f.write("-" * 30 + "\n")
            f.write(f"Accuracy:    {self.results['accuracy']*100:.2f}%\n")
            f.write(f"Precision:   {self.results['precision']*100:.2f}%\n")
            f.write(f"Recall:      {self.results['recall']*100:.2f}%\n")
            f.write(f"F1-Score:    {self.results['f1']*100:.2f}%\n")
            
            if "specificity" in self.results:
                f.write(f"Specificity: {self.results['specificity']*100:.2f}%\n")
            if "roc_auc" in self.results:
                f.write(f"ROC-AUC:     {self.results['roc_auc']*100:.2f}%\n")
            
            f.write("\nCONFUSION MATRIX\n")
            f.write("-" * 30 + "\n")
            if "tp" in self.results:
                f.write(f"True Positives:  {self.results['tp']}\n")
                f.write(f"True Negatives:  {self.results['tn']}\n")
                f.write(f"False Positives: {self.results['fp']}\n")
                f.write(f"False Negatives: {self.results['fn']}\n")
        
        print_success(f"Report saved: {filepath}")
        return str(filepath)
