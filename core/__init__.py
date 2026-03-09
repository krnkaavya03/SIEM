"""
SIEM Hybrid Framework - Core Package
Contains all core detection and analysis modules
Supports real system log collection, parsing, and threat detection
"""

__version__ = "1.0.0"
__author__ = "SIEM Framework Project"

# Import core modules for convenient access
from .log_collector import LogCollector
from .log_parser import LogParser
from .detection_engine import DetectionEngine
from .correlation_engine import CorrelationEngine
from .alert_manager import AlertManager
from .statistics_engine import StatisticsEngine

# Expose modules when importing core package
__all__ = [
    'LogCollector',
    'LogParser',
    'DetectionEngine',
    'CorrelationEngine',
    'AlertManager',
    'StatisticsEngine'
]
