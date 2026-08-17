"""
CMMC Artifact Gathering Tool
Collects compliance artifacts from Windows endpoints for CMMC assessment.
"""

__version__ = "0.9.0"
__author__ = "Tenguard Security"

from .gatherer import CMMCGatherer

__all__ = ["CMMCGatherer"]
