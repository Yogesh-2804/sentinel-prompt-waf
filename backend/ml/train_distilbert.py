"""
Fine-tuning Script for Layer 3 DistilBERT Sequence Classifier
Trains distilbert-base-uncased on sentinelprompt_dataset_v1 (train.json), evaluates on val.json,
and saves model artifacts to backend/models/distilbert_sentinelprompt/.
"""

import os
import sys
import json
import time
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from transformers import AutoTokenizer, AutoModelForSequenceClassification, get_linear_schedule_with_warmup
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

# Ensure reproducibility
torch.manual_seed(42)

# Directory Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPLITS_DIR = os.path.join(BASE_DIR, "data", "datasets", "splits")
MODEL_OUTPUT_DIR = os.path.join(BASE_DIR, "models", "distilbert_sentinelprompt")

os.makedirs(MODEL_OUTPUT_DIR, exist_ok=True)


class PromptDataset(Dataset):
    """PyTorch Dataset for Prompt Injection Classification."""
    def __init__(self, samples, tokenizer, max_length=128):
        self.texts = [s["text"] for s in samples]
        self.labels = [s["binary_label"] for s in samples]
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])
        label = self.labels[idx]

        encoding = self.tokenizer(
            text,
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt"
        )

        return {
            "input_ids": encoding["input_ids"].flatten(),
            "attention_mask": encoding["attention_mask"].flatten(),
            "labels": torch.tensor(label, dtype=torch.long)
        }


def load_dataset_split(filename):
    path = os.path.join(SPLITS_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset split not found at: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def train_model():
    print("=========================================================")
    print("      SentinelPrompt - Fine-Tuning Layer 3 DistilBERT    ")
    print("=========================================================\n")
    sys.stdout.flush()

    # 1. Load Data
    train_samples = load_dataset_split("train.json")
    val_samples = load_dataset_split("val.json")
    print(f"Loaded {len(train_samples)} training samples and {len(val_samples)} validation samples.")
    sys.stdout.flush()

    model_name = "distilbert-base-uncased"
    print(f"Initializing Tokenizer & Model: '{model_name}'...")
    sys.stdout.flush()

    tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=False)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Training device: {device}")
    sys.stdout.flush()
    model.to(device)

    # Create DataLoaders
    train_dataset = PromptDataset(train_samples, tokenizer)
    val_dataset = PromptDataset(val_samples, tokenizer)

    train_loader = DataLoader(train_dataset, batch_size=8, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=8, shuffle=False)

    epochs = 5
    optimizer = AdamW(model.parameters(), lr=5e-5, weight_decay=0.01)
    total_steps = len(train_loader) * epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=0, num_training_steps=total_steps)

    start_time = time.time()

    print("\nStarting Training Loop...")
    sys.stdout.flush()
    for epoch in range(epochs):
        model.train()
        total_train_loss = 0.0

        for batch in train_loader:
            optimizer.zero_grad()
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            outputs = model(input_ids, attention_mask=attention_mask, labels=labels)
            loss = outputs.loss
            total_train_loss += loss.item()

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()

        avg_train_loss = total_train_loss / len(train_loader)

        # Validation Evaluation
        model.eval()
        val_preds = []
        val_targets = []
        total_val_loss = 0.0

        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch["input_ids"].to(device)
                attention_mask = batch["attention_mask"].to(device)
                labels = batch["labels"].to(device)

                outputs = model(input_ids, attention_mask=attention_mask, labels=labels)
                loss = outputs.loss
                total_val_loss += loss.item()

                logits = outputs.logits
                preds = torch.argmax(logits, dim=1).cpu().numpy()
                val_preds.extend(preds)
                val_targets.extend(labels.cpu().numpy())

        avg_val_loss = total_val_loss / len(val_loader)
        acc = accuracy_score(val_targets, val_preds)
        prec, rec, f1, _ = precision_recall_fscore_support(val_targets, val_preds, average="binary", zero_division=0)

        print(f"Epoch {epoch+1}/{epochs} | Train Loss: {avg_train_loss:.4f} | Val Loss: {avg_val_loss:.4f} | Val Acc: {acc:.4f} | Val F1: {f1:.4f}")
        sys.stdout.flush()

    total_time = round(time.time() - start_time, 2)
    print(f"\nTraining completed in {total_time}s.")
    sys.stdout.flush()

    # 2. Save Trained Model & Tokenizer Artifacts
    print(f"Saving model artifacts to '{MODEL_OUTPUT_DIR}'...")
    sys.stdout.flush()
    model.save_pretrained(MODEL_OUTPUT_DIR)
    tokenizer.save_pretrained(MODEL_OUTPUT_DIR)

    metrics_log = {
        "model_name": model_name,
        "epochs": epochs,
        "training_time_seconds": total_time,
        "final_train_loss": round(avg_train_loss, 4),
        "final_val_loss": round(avg_val_loss, 4),
        "val_accuracy": round(float(acc), 4),
        "val_precision": round(float(prec), 4),
        "val_recall": round(float(rec), 4),
        "val_f1_score": round(float(f1), 4),
        "device_used": str(device)
    }

    with open(os.path.join(MODEL_OUTPUT_DIR, "training_metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics_log, f, indent=2)

    print("DistilBERT/BERT Model Artifacts Successfully Saved!")
    sys.stdout.flush()
    return metrics_log


if __name__ == "__main__":
    train_model()
