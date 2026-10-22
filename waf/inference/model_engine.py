"""Handcrafted heuristic scorer used by the prototype.

This module does not load Transformer or ONNX model weights. The legacy factory
name is retained for callers, but a supplied model path raises an explicit
error rather than silently pretending that a model was loaded.
"""

import math
import re
import time
from typing import Dict, List, Optional


class WafHeuristicScorer:
    """Lexical, entropy, and punctuation heuristic returning a score in [0, 1]."""

    def __init__(self):
        self.latency_history: List[float] = []

    def predict(self, canonical_text: str) -> float:
        start = time.perf_counter()
        score = self._score(canonical_text)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        self.latency_history.append(elapsed_ms)
        if len(self.latency_history) > 1000:
            self.latency_history.pop(0)
        return min(max(float(score), 0.0), 1.0)

    @staticmethod
    def _score(text: str) -> float:
        if not text:
            return 0.0

        lowered = text.lower()
        score = 0.0
        signatures = [
            (r"union\s+select", 0.85),
            (r"information_schema", 0.90),
            (r"<script[\s>]", 0.90),
            (r"javascript:", 0.85),
            (r"onload\s*=", 0.80),
            (r"onerror\s*=", 0.80),
            (r"\.\./\.\./", 0.85),
            (r"/etc/passwd", 0.95),
            (r"/bin/(sh|bash)", 0.95),
            (r"cmd\.exe", 0.95),
            (r"powershell", 0.90),
            (r"\$\{jndi:", 0.98),
            (r"eval\(", 0.75),
            (r"exec\(", 0.75),
            (r"benchmark\(", 0.85),
            (r"sleep\(\d+\)", 0.80),
            (r"select.*from.*where", 0.80),
            (r"waitfor\s+delay", 0.85),
            (r"or\s+1\s*=\s*1", 0.85),
            (r"'\s+or\s+'", 0.80),
            (r"--\s*$", 0.65),
            (r";\s*drop\s+table", 0.95),
            (r"<!entity.*system", 0.92),
        ]
        for pattern, weight in signatures:
            if re.search(pattern, lowered):
                score = max(score, weight)

        length = len(text)
        if length > 20:
            counts: Dict[str, int] = {}
            for char in text:
                counts[char] = counts.get(char, 0) + 1
            entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
            if entropy > 4.6 and length > 40:
                score = max(score, 0.70)
            elif entropy > 4.3 and length > 60:
                score = max(score, 0.55)

        punctuation_count = len(re.findall(r"['\";`<>\(\)\{\}$|&!]", text))
        if punctuation_count / max(length, 1) > 0.18 and length > 15:
            score = max(score, 0.65)
        return score

    @property
    def avg_latency_ms(self) -> float:
        if not self.latency_history:
            return 0.0
        return sum(self.latency_history) / len(self.latency_history)


def create_default_scorer(model_path: Optional[str] = None) -> WafHeuristicScorer:
    """Return the bundled heuristic; no trained model is shipped or loaded."""
    if model_path:
        raise NotImplementedError("Transformer/ONNX model loading is not implemented in this prototype.")
    return WafHeuristicScorer()


# Backward-compatible import alias. This class is not neural and does not load ONNX.
WafNeuralScorer = WafHeuristicScorer
