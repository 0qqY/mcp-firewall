"""Shared classification metrics. Scores are P(INJECTION)."""

import numpy as np
from sklearn.metrics import roc_auc_score


def binary_metrics(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    preds = scores >= threshold
    tp = int(np.sum(preds & (labels == 1)))
    fp = int(np.sum(preds & (labels == 0)))
    fn = int(np.sum(~preds & (labels == 1)))
    tn = int(np.sum(~preds & (labels == 0)))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        # False positives are what make people switch a firewall off.
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "auroc": float(roc_auc_score(labels, scores)) if len(set(labels.tolist())) == 2 else float("nan"),
    }
