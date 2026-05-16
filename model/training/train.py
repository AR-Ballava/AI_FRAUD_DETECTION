"""Minimal training/export entry point for a single .pt fraud classifier.

Expected CSV format in model/datasets/training.csv:
text,label
"Urgent job offer ...",scam_recruitment_email

The script intentionally keeps feature extraction aligned with app.inference so the
exported checkpoint can be loaded by the model service without extra assets.
"""

from __future__ import annotations

import csv
import pathlib
import sys

import torch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

from app.inference import FraudLinearModel, LABELS, _feature_vector  # noqa: E402


def load_rows(path: pathlib.Path) -> list[tuple[str, int]]:
    rows: list[tuple[str, int]] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            label = row.get("label", "")
            if label not in LABELS:
                continue
            rows.append((row.get("text", ""), LABELS.index(label)))
    return rows


def main() -> None:
    dataset = ROOT / "datasets" / "training.csv"
    output = ROOT / "models" / "job_fraud_model.pt"
    if not dataset.exists():
        raise SystemExit(f"Dataset not found: {dataset}")

    rows = load_rows(dataset)
    if not rows:
        raise SystemExit("No valid rows found in dataset")

    model = FraudLinearModel(output_size=len(LABELS))
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.003)
    loss_fn = torch.nn.CrossEntropyLoss()

    x = torch.cat([_feature_vector(text) for text, _ in rows], dim=0)
    y = torch.tensor([label for _, label in rows], dtype=torch.long)

    model.train()
    for _ in range(300):
        optimizer.zero_grad()
        loss = loss_fn(model(x), y)
        loss.backward()
        optimizer.step()

    output.parent.mkdir(parents=True, exist_ok=True)
    torch.save({"state_dict": model.state_dict(), "labels": LABELS}, output)
    print(f"Saved {output}")


if __name__ == "__main__":
    main()

