"""Main CMMC Gatherer orchestrator."""

import logging
from typing import Dict, List, Optional
from .collectors.onprem.endpoint_collector import EndpointCollector
from .collectors.onprem.ad_collector import ActiveDirectoryCollector
from .collectors.onprem.event_log_collector import EventLogCollector
from .collectors.onprem.policy_collector import PolicyCollector
from .exporters.exporter_factory import ExporterFactory
from .models.artifacts import ArtifactCollection

logger = logging.getLogger(__name__)


class CMMCGatherer:
    """Coordinates artifact collection and export for a CMMC assessment.

    Initialises all collectors on construction. Call collect_all() to gather
    data, then export() to write results in any supported format.
    """

    def __init__(self, config: Optional[Dict] = None):
        logger.info("Initializing CMMC Gatherer...")
        self.config = config or {}
        self.endpoint_collector = EndpointCollector()
        self.ad_collector = ActiveDirectoryCollector()
        self.event_log_collector = EventLogCollector()
        self.policy_collector = PolicyCollector()
        self.artifacts = ArtifactCollection()
        logger.info("Gatherer ready - collectors initialized")

    def collect_all(self) -> ArtifactCollection:
        """Run all collectors and return the populated ArtifactCollection."""
        logger.info("=" * 60)
        logger.info("STARTING FULL ARTIFACT COLLECTION")
        logger.info("=" * 60)

        logger.info("[1/4] Collecting endpoint data...")
        self.artifacts.endpoints = self.endpoint_collector.collect()
        logger.info(f"  Found {len(self.artifacts.endpoints)} endpoint(s)")

        logger.info("[2/4] Collecting Active Directory objects...")
        self.artifacts.ad_objects = self.ad_collector.collect()
        logger.info(f"  Found {len(self.artifacts.ad_objects)} AD object(s)")

        logger.info("[3/4] Collecting security event logs...")
        self.artifacts.security_events = self.event_log_collector.collect()
        logger.info(f"  Found {len(self.artifacts.security_events)} event(s)")

        logger.info("[4/4] Collecting policy configurations...")
        self.artifacts.policies = self.policy_collector.collect()
        logger.info(f"  Found {len(self.artifacts.policies)} policy(ies)")

        total = (
            len(self.artifacts.endpoints) + len(self.artifacts.ad_objects) +
            len(self.artifacts.security_events) + len(self.artifacts.policies)
        )
        logger.info("=" * 60)
        logger.info(f"COLLECTION COMPLETE — {total} total artifacts")
        logger.info("=" * 60)
        return self.artifacts

    def collect_endpoints_only(self) -> ArtifactCollection:
        """Collect only endpoint data (faster than collect_all)."""
        logger.info("Quick collection: endpoints only")
        self.artifacts.endpoints = self.endpoint_collector.collect()
        logger.info(f"Collected {len(self.artifacts.endpoints)} endpoint(s)")
        return self.artifacts

    def collect_policies_only(self) -> ArtifactCollection:
        """Collect only policy configurations."""
        logger.info("Quick collection: policies only")
        self.artifacts.policies = self.policy_collector.collect()
        logger.info(f"Collected {len(self.artifacts.policies)} policy(ies)")
        return self.artifacts

    def export(
        self,
        format_type: str,
        output_path: str,
        customer_name: Optional[str] = None,
        assessment_id: Optional[str] = None,
    ) -> bool:
        """Export collected artifacts to the specified format.

        Args:
            format_type: One of 'json', 'csv', 'xml', 'html', 'msp_report'.
            output_path: Writable file path for the output.
            customer_name: Client name (used by msp_report).
            assessment_id: Assessment identifier (used by msp_report).

        Returns:
            True on success, False on failure (errors are logged).
        """
        logger.info(f"Exporting to {format_type.upper()}: {output_path}")
        try:
            exporter = ExporterFactory.create_exporter(format_type)
            if not exporter:
                logger.error(f"Export format '{format_type}' not supported")
                return False
            return exporter.export(
                self.artifacts, output_path,
                customer_name=customer_name,
                assessment_id=assessment_id,
            )
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False

    def export_multiple(self, formats: List[str], output_dir: str) -> Dict[str, bool]:
        """Export to multiple formats, writing files into output_dir.

        Returns a dict mapping each format to its success/failure status.
        """
        return {
            fmt: self.export(fmt, f"{output_dir}/artifacts.{fmt}")
            for fmt in formats
        }
