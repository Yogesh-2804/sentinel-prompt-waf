import time
import pytest
from app.services.decision_engine import DecisionEngine


def test_performance_latency_overhead():
    engine = DecisionEngine()
    prompt = "Explain quantum computing principles and how quantum superposition works."

    # Warm-up run
    engine.evaluate_prompt(prompt)

    # Benchmark 100 sequential prompt evaluations
    start = time.perf_counter()
    iterations = 100
    for _ in range(iterations):
        res = engine.evaluate_prompt(prompt)
        assert res["verdict"] == "FORWARDED"
    
    elapsed_total_ms = (time.perf_counter() - start) * 1000
    avg_latency_per_prompt = elapsed_total_ms / iterations

    print(f"\n[BENCHMARK RESULT] Total time for {iterations} prompts: {elapsed_total_ms:.2f}ms")
    print(f"[BENCHMARK RESULT] Average Latency per Prompt across 6 layers: {avg_latency_per_prompt:.2f}ms")

    # Assert total middleware overhead is under 250ms per prompt for deep Transformer inference on CPU
    assert avg_latency_per_prompt < 250.0
