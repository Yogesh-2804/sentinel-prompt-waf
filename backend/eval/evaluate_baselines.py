"""
SentinelPrompt - Experimental Evaluation Framework (Phase 8)
Benchmarking 4 Comparative Baselines over held-out test.json split (16 samples).

Baselines Evaluated:
1. Baseline 1: No Defense (Unprotected Gateway)
2. Baseline 2: Static Regex & Keyword Filtering (Layer 1 + Layer 2)
3. Baseline 3: Supervised ML Classifier (Layer 3 DistilBERT only)
4. SentinelPrompt: Adaptive Multi-Layer Security Gateway (Full 5-Layer Architecture)

Persists results to:
- backend/reports/evaluation_report.json
- backend/reports/confusion_matrices.json
"""

import os
import sys
import json
import time
from typing import Dict, Any, List

# Ensure backend root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.services.decision_engine import DecisionEngine
from app.services.regex_detector import RegexDetector
from app.services.keyword_detector import KeywordDetector
from app.services.ml_detector import MLDetector

SPLITS_DIR = os.path.join(BASE_DIR, "data", "datasets", "splits")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


def load_test_split() -> List[Dict[str, Any]]:
    test_path = os.path.join(SPLITS_DIR, "test.json")
    if not os.path.exists(test_path):
        raise FileNotFoundError(f"Test split not found at: {test_path}")
    with open(test_path, "r", encoding="utf-8") as f:
        return json.load(f)


def compute_metrics(tp: int, tn: int, fp: int, fn: int, total_latency_ms: float, total_samples: int) -> Dict[str, Any]:
    acc = (tp + tn) / total_samples if total_samples > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0
    avg_latency = total_latency_ms / total_samples if total_samples > 0 else 0.0

    return {
        "confusion_matrix": {"TP": tp, "TN": tn, "FP": fp, "FN": fn},
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "false_negative_rate_fnr": round(fnr, 4),
        "false_positive_rate_fpr": round(fpr, 4),
        "avg_latency_ms": round(avg_latency, 2),
        "project_targets_met": {
            "fnr_under_5_percent": fnr < 0.05,
            "fpr_under_2_percent": fpr < 0.02
        }
    }


def run_evaluation():
    print("=========================================================")
    print("     SentinelPrompt - Experimental Evaluation Framework  ")
    print("=========================================================\n")
    sys.stdout.flush()

    test_samples = load_test_split()
    print(f"Loaded {len(test_samples)} held-out test samples from test.json.\n")
    sys.stdout.flush()

    regex_detector = RegexDetector()
    keyword_detector = KeywordDetector()
    ml_detector = MLDetector()
    decision_engine = DecisionEngine()

    results = {}
    confusion_matrices = {}

    # -------------------------------------------------------------
    # BASELINE 1: No Defense (Unprotected Gateway)
    # -------------------------------------------------------------
    print("Evaluating Baseline 1: No Defense (Unprotected Gateway)...")
    tp1, tn1, fp1, fn1 = 0, 0, 0, 0
    t1_start = time.perf_counter()
    for s in test_samples:
        actual = s["binary_label"]  # 1 = malicious, 0 = benign
        predicted = 0  # Always forwards
        if actual == 1 and predicted == 1: tp1 += 1
        elif actual == 0 and predicted == 0: tn1 += 1
        elif actual == 0 and predicted == 1: fp1 += 1
        elif actual == 1 and predicted == 0: fn1 += 1
    t1_ms = (time.perf_counter() - t1_start) * 1000
    results["baseline_1_no_defense"] = compute_metrics(tp1, tn1, fp1, fn1, t1_ms, len(test_samples))
    confusion_matrices["baseline_1_no_defense"] = {"TP": tp1, "TN": tn1, "FP": fp1, "FN": fn1}

    # -------------------------------------------------------------
    # BASELINE 2: Static Regex & Keyword Filtering (Layers 1 & 2)
    # -------------------------------------------------------------
    print("Evaluating Baseline 2: Static Regex & Keyword Filtering...")
    tp2, tn2, fp2, fn2 = 0, 0, 0, 0
    t2_start = time.perf_counter()
    for s in test_samples:
        text = s["text"]
        actual = s["binary_label"]
        res_r = regex_detector.analyze(text)
        res_k = keyword_detector.analyze(text)
        predicted = 1 if (res_r["is_triggered"] or res_k["is_triggered"]) else 0
        if actual == 1 and predicted == 1: tp2 += 1
        elif actual == 0 and predicted == 0: tn2 += 1
        elif actual == 0 and predicted == 1: fp2 += 1
        elif actual == 1 and predicted == 0: fn2 += 1
    t2_ms = (time.perf_counter() - t2_start) * 1000
    results["baseline_2_static_regex_keyword"] = compute_metrics(tp2, tn2, fp2, fn2, t2_ms, len(test_samples))
    confusion_matrices["baseline_2_static_regex_keyword"] = {"TP": tp2, "TN": tn2, "FP": fp2, "FN": fn2}

    # -------------------------------------------------------------
    # BASELINE 3: Supervised ML Classifier (DistilBERT only)
    # -------------------------------------------------------------
    print("Evaluating Baseline 3: Supervised ML (DistilBERT only)...")
    tp3, tn3, fp3, fn3 = 0, 0, 0, 0
    t3_start = time.perf_counter()
    for s in test_samples:
        text = s["text"]
        actual = s["binary_label"]
        res_m = ml_detector.analyze(text)
        predicted = 1 if res_m["is_triggered"] else 0
        if actual == 1 and predicted == 1: tp3 += 1
        elif actual == 0 and predicted == 0: tn3 += 1
        elif actual == 0 and predicted == 1: fp3 += 1
        elif actual == 1 and predicted == 0: fn3 += 1
    t3_ms = (time.perf_counter() - t3_start) * 1000
    results["baseline_3_supervised_ml_distilbert"] = compute_metrics(tp3, tn3, fp3, fn3, t3_ms, len(test_samples))
    confusion_matrices["baseline_3_supervised_ml_distilbert"] = {"TP": tp3, "TN": tn3, "FP": fp3, "FN": fn3}

    # -------------------------------------------------------------
    # BASELINE 4: SentinelPrompt (Full 5-Layer Security Gateway)
    # -------------------------------------------------------------
    print("Evaluating SentinelPrompt (Full 5-Layer Security Gateway)...")
    tp4, tn4, fp4, fn4 = 0, 0, 0, 0
    t4_start = time.perf_counter()
    for s in test_samples:
        text = s["text"]
        actual = s["binary_label"]
        res_sp = decision_engine.evaluate_prompt(text)
        predicted = 1 if res_sp["is_malicious"] else 0
        if actual == 1 and predicted == 1: tp4 += 1
        elif actual == 0 and predicted == 0: tn4 += 1
        elif actual == 0 and predicted == 1: fp4 += 1
        elif actual == 1 and predicted == 0: fn4 += 1
    t4_ms = (time.perf_counter() - t4_start) * 1000
    results["sentinelprompt_full_gateway"] = compute_metrics(tp4, tn4, fp4, fn4, t4_ms, len(test_samples))
    confusion_matrices["sentinelprompt_full_gateway"] = {"TP": tp4, "TN": tn4, "FP": fp4, "FN": fn4}

    # Display Comparative Results Table
    print("\n=========================================================")
    print("            EXPERIMENTAL EVALUATION RESULTS              ")
    print("=========================================================")
    header = f"{'Baseline Architecture':<35} | {'Acc':<6} | {'Prec':<6} | {'Rec':<6} | {'F1':<6} | {'FNR':<6} | {'FPR':<6}"
    print(header)
    print("-" * len(header))

    for key, data in results.items():
        name = key.replace("_", " ").title()
        print(f"{name:<35} | {data['accuracy']:<6.4f} | {data['precision']:<6.4f} | {data['recall']:<6.4f} | {data['f1_score']:<6.4f} | {data['false_negative_rate_fnr']:<6.4f} | {data['false_positive_rate_fpr']:<6.4f}")

    print("=========================================================\n")
    sys.stdout.flush()

    # Save JSON reports
    eval_report_path = os.path.join(REPORTS_DIR, "evaluation_report.json")
    cm_report_path = os.path.join(REPORTS_DIR, "confusion_matrices.json")

    with open(eval_report_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    with open(cm_report_path, "w", encoding="utf-8") as f:
        json.dump(confusion_matrices, f, indent=2)

    print(f"Evaluation report saved to '{eval_report_path}'")
    print(f"Confusion matrices saved to '{cm_report_path}'")
    sys.stdout.flush()

    return results


if __name__ == "__main__":
    run_evaluation()
