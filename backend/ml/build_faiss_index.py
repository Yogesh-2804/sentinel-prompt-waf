"""
FAISS Vector Index Generator for Layer 4 Semantic Detection.
Vectorizes verified prompt injection attacks using SentenceTransformers (all-MiniLM-L6-v2)
and builds a local FAISS Inner Product (Cosine Similarity) index.
"""

import os
import sys
import json
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPLITS_DIR = os.path.join(BASE_DIR, "data", "datasets", "splits")
MODEL_OUTPUT_DIR = os.path.join(BASE_DIR, "models")
INDEX_PATH = os.path.join(MODEL_OUTPUT_DIR, "faiss_threat_index.bin")
METADATA_PATH = os.path.join(MODEL_OUTPUT_DIR, "faiss_threat_metadata.json")

os.makedirs(MODEL_OUTPUT_DIR, exist_ok=True)


def load_malicious_prompts():
    """Loads verified prompt injection attack samples from train.json and val.json."""
    malicious_samples = []
    
    for split_file in ["train.json", "val.json"]:
        path = os.path.join(SPLITS_DIR, split_file)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    if item.get("binary_label") == 1:
                        malicious_samples.append({
                            "id": item.get("id"),
                            "text": item.get("text"),
                            "attack_family": item.get("attack_family", "prompt_injection"),
                            "source_dataset": item.get("source_dataset", "sentinelprompt_v1")
                        })
                        
    return malicious_samples


def build_index():
    print("=========================================================")
    print("      SentinelPrompt - FAISS Threat Indexing Service     ")
    print("=========================================================\n")
    sys.stdout.flush()

    samples = load_malicious_prompts()
    print(f"Loaded {len(samples)} verified malicious threat prompts from dataset splits.")
    sys.stdout.flush()

    if not samples:
        raise ValueError("No malicious samples found in dataset splits!")

    model_name = "sentence-transformers/all-MiniLM-L6-v2"
    print(f"Loading Embedding Model: '{model_name}'...")
    sys.stdout.flush()

    model = SentenceTransformer(model_name)

    texts = [s["text"] for s in samples]
    print(f"Generating 384-dimensional L2-normalized embeddings for {len(texts)} prompts...")
    sys.stdout.flush()

    embeddings = model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
    embeddings = np.array(embeddings, dtype=np.float32)

    dimension = embeddings.shape[1]  # 384
    print(f"Embedding Matrix Shape: {embeddings.shape} (Dimension: {dimension})")
    sys.stdout.flush()

    # IndexFlatIP computes exact Cosine Similarity for L2-normalized vectors
    index = faiss.IndexFlatIP(dimension)
    index.add(embeddings)

    print(f"Added {index.ntotal} vectors to FAISS FlatIP Index.")
    sys.stdout.flush()

    # Save index and metadata
    print(f"Saving FAISS index to '{INDEX_PATH}'...")
    faiss.write_index(index, INDEX_PATH)

    print(f"Saving threat metadata to '{METADATA_PATH}'...")
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(samples, f, indent=2)

    print("\nFAISS Vector Index & Threat Metadata Successfully Built!")
    sys.stdout.flush()
    return index.ntotal


if __name__ == "__main__":
    build_index()
