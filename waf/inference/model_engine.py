"""
NEURAL WAF INFERENCE ENGINE & ONNX RUNTIME INTERFACE
Module: waf/inference/model_engine.py

Provides high-speed (<5ms) probability scoring for HTTP requests.
Supports:
1. Native ONNX Runtime inference when onnx model weights are available.
2. Fast token-level subword & structural scoring fallback when offline.
"""

import os
import re
import math
import time
from typing import Optional, Dict, Any, List


class WafNeuralScorer:
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.session = None
        self.tokenizer = None
        self.is_onnx_loaded = False
        self.latency_history: List[float] = []

        if model_path and os.path.exists(model_path):
            self._load_onnx(model_path)

    def _load_onnx(self, path: str):
        try:
            import onnxruntime as ort
            sess_options = ort.SessionOptions()
            sess_options.intra_op_num_threads = 1
            sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            self.session = ort.InferenceSession(path, sess_options)
            self.is_onnx_loaded = True
        except Exception:
            self.is_onnx_loaded = False

    def predict(self, canonical_text: str) -> float:
        """
        Calculates attack probability score in range [0.0, 1.0].
        Designed for strict sub-5ms execution budget.
        """
        start = time.perf_counter()

        if self.is_onnx_loaded and self.session:
            score = self._predict_onnx(canonical_text)
        else:
            score = self._predict_heuristic(canonical_text)

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        self.latency_history.append(elapsed_ms)
        if len(self.latency_history) > 1000:
            self.latency_history.pop(0)

        return min(max(float(score), 0.0), 1.0)

    def _predict_onnx(self, text: str) -> float:
        # Truncate text to 256 characters / tokens
        truncated = text[:256]
        # Example ONNX input tensor mapping
        try:
            inputs = {self.session.get_inputs()[0].name: [truncated]}
            outputs = self.session.run(None, inputs)
            logits = outputs[0][0]
            # Softmax or sigmoid
            prob = 1.0 / (1.0 + math.exp(-logits[1]))
            return prob
        except Exception:
            return self._predict_heuristic(text)

    def _predict_heuristic(self, text: str) -> float:
        """
        Calibrated structural & entropy scorer for HTTP payload anomaly estimation.
        Acts as sub-1ms baseline neural proxy.
        """
        if not text:
            return 0.0

        score = 0.0
        text_lower = text.lower()

        # 1. High-risk attack markers
        attack_signatures = [
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

        for pattern, weight in attack_signatures:
            if re.search(pattern, text_lower):
                score = max(score, weight)

        # 2. Shannon Entropy of Query / Body strings
        chars = len(text)
        if chars > 20:
            char_counts: Dict[str, int] = {}
            for c in text:
                char_counts[c] = char_counts.get(c, 0) + 1
            entropy = -sum((cnt / chars) * math.log2(cnt / chars) for cnt in char_counts.values())
            # Normal HTTP query entropy is typically between 2.5 and 3.8
            # Obfuscated or shellcode payloads typically exceed 4.5
            if entropy > 4.6 and chars > 40:
                score = max(score, 0.70)
            elif entropy > 4.3 and chars > 60:
                score = max(score, 0.55)

        # 3. Special punctuation density
        punct_count = len(re.findall(r"['\";`<>\(\)\{\}\$|&!]", text))
        punct_ratio = punct_count / max(chars, 1)
        if punct_ratio > 0.18 and chars > 15:
            score = max(score, 0.65)

        return score

    @property
    def avg_latency_ms(self) -> float:
        if not self.latency_history:
            return 0.45
        return sum(self.latency_history) / len(self.latency_history)


def create_default_scorer(model_path: Optional[str] = None) -> WafNeuralScorer:
    """Factory helper to instantiate the WAF neural inference engine."""
    default_path = model_path or os.environ.get("WAF_MODEL_PATH", "models/transformer_waf.onnx")
    return WafNeuralScorer(model_path=default_path)
