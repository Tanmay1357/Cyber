"""
Source package for NIDS with XAI.

Network Intrusion Detection System with Explainable AI

This package provides:
    - DataLoader: Load CIC-IDS2017/2018 datasets
    - Preprocessor: Feature engineering and data transformation
    - ModelTrainer: Random Forest classifier training
    - Evaluator: Comprehensive model evaluation
    - Explainer: SHAP and LIME explanations
    - Classifier: Classify new network traffic
    - pcap_converter: Convert PCAP files to CSV

Utility modules:
    - utils: Console output and formatting

Author: Final Year CS Project
"""

from .data_loader import DataLoader
from .preprocessor import Preprocessor
from .model_trainer import ModelTrainer
from .evaluator import Evaluator
from .explainer import Explainer
from .classifier import Classifier

__all__ = [
    'DataLoader',
    'Preprocessor',
    'ModelTrainer',
    'Evaluator',
    'Explainer',
    'Classifier',
]

__version__ = '1.0.0'
__author__ = 'Final Year CS Project'
