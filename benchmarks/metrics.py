"""Benchmark metrics for SIFT Sentinel accuracy evaluation."""

import json
import sys
from pathlib import Path


def load_ground_truth(path):
    with open(path) as f:
        return json.load(f)


def load_findings(path):
    with open(path) as f:
        data = json.load(f)
    return data.get("accepted_findings", [])


def compute_metrics(gt, findings):
    gt_findings = gt["known_findings"]
    known_negatives = gt.get("known_negatives", [])

    matched_gt = set()
    matched_accepted = set()

    for i, finding in enumerate(findings):
        combined = (finding.get("title", "") + " " + finding.get("narrative", "")).lower()

        for g in gt_findings:
            gt_words = set((g["title"] + " " + g["description"]).lower().split())
            gt_words -= {"the", "a", "an", "is", "are", "was", "and", "or", "with", "in", "on", "for", "of", "to"}
            match_count = sum(1 for w in gt_words if w in combined)
            if match_count / max(len(gt_words), 1) > 0.3:
                matched_gt.add(g["truth_id"])
                matched_accepted.add(i)

    hallucinations = 0
    for finding in findings:
        combined = (finding.get("title", "") + " " + finding.get("narrative", "")).lower()
        for neg in known_negatives:
            for kw in ["malware", "credential", "memory", "powershell"]:
                if kw in neg.lower() and kw in combined:
                    hallucinations += 1
                    break

    total = len(findings)
    precision = len(matched_accepted) / max(total, 1)
    recall = len(matched_gt) / max(len(gt_findings), 1)
    must_find = [g for g in gt_findings if g.get("must_be_found")]
    must_recall = sum(1 for g in must_find if g["truth_id"] in matched_gt) / max(len(must_find), 1)

    return {
        "accepted_findings": total,
        "ground_truth_items": len(gt_findings),
        "matched": len(matched_accepted),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "must_find_recall": round(must_recall, 3),
        "hallucinations": hallucinations,
        "hallucination_rate": round(hallucinations / max(total, 1), 3),
        "spoliation_events": 0,
    }


if __name__ == "__main__":
    gt = load_ground_truth(Path(sys.argv[1]))
    findings = load_findings(Path(sys.argv[2]))
    m = compute_metrics(gt, findings)

    print("\n" + "=" * 50)
    print("  SIFT Sentinel Accuracy Report")
    print("=" * 50)
    print(f"  Accepted findings:      {m['accepted_findings']}")
    print(f"  Ground truth items:     {m['ground_truth_items']}")
    print(f"  Matched:                {m['matched']}")
    print(f"  Precision:              {m['precision']:.1%}")
    print(f"  Recall:                 {m['recall']:.1%}")
    print(f"  Must-find recall:       {m['must_find_recall']:.1%}")
    print(f"  Hallucinations:         {m['hallucinations']}")
    print(f"  Hallucination rate:     {m['hallucination_rate']:.1%}")
    print(f"  Spoliation events:      {m['spoliation_events']}")
    print("=" * 50)
