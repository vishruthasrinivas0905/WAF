"""
WAF NEURAL INFERENCE ENGINE
Module: waf/inference/__init__.py
"""

from .model_engine import WafNeuralScorer, create_default_scorer

__all__ = ["WafNeuralScorer", "create_default_scorer"]
