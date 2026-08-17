"""Collection health logging.

Captures every WARNING/ERROR emitted by any collector during one tenant's
run, so a real failure is visible in the report itself, not only in the
console — closing the exact gap this session kept running into: a
collector-level failure (a bad Graph call, a permission gap, an unexpected
response shape) only ever showed up as a console log line, while the HTML
report just silently showed fewer rows or a zero count with no visible
explanation of why.

Deliberately implemented as a ``logging.Handler`` attached to the
``cmmc_gatherer`` logger, rather than touching every collector's internal
try/except blocks. Every collector in this project already calls
``logger.warning()``/``logger.error()`` on failure — that's how every real
pilot issue this session got diagnosed from the console in the first
place. This taps into that existing, already-correct behavior centrally,
so any future collector automatically gets health reporting for free the
moment it logs a warning or error, with no per-file changes required.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List


@dataclass
class HealthLogEntry:
    timestamp: str
    level: str      # 'WARNING' or 'ERROR'
    source: str      # dotted logger name, e.g. cmmc_gatherer.collectors.cloud.cloud_policy_collector
    message: str


class CollectionHealthRecorder(logging.Handler):
    """A logging.Handler that captures WARNING+ records into a list, scoped
    to one tenant's collection run.

    Usage (see orchestrator.run_one()): attach to the 'cmmc_gatherer'
    logger before collection starts, remove it once collection finishes,
    then read .entries. Child loggers throughout this project (every
    module uses logging.getLogger(__name__)) propagate up to this handler
    automatically — standard Python logging behavior, not something each
    collector needs to opt into.
    """

    def __init__(self):
        super().__init__(level=logging.WARNING)
        self.entries: List[HealthLogEntry] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.entries.append(HealthLogEntry(
                # record.created is the epoch timestamp the logging module
                # itself set at the moment the LogRecord was created — using
                # datetime.now() here instead measured the time this HANDLER
                # got around to processing it, which drifts under any
                # buffering and is off by however long emit() takes to run.
                # record.created is the actual, correct source of truth.
                timestamp=datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
                level=record.levelname,
                source=record.name,
                message=record.getMessage(),
            ))
        except Exception:
            # A logging handler must never itself raise — that could break
            # logging for the rest of the run. handleError (not a bare
            # except: pass) respects logging.raiseExceptions and prints
            # the real traceback to stderr in debug scenarios, rather than
            # silently hiding a genuine formatting bug in this handler
            # itself, which a bare pass would do.
            self.handleError(record)

    @staticmethod
    def readable_source(dotted_name: str) -> str:
        """'cmmc_gatherer.collectors.cloud.cloud_policy_collector' ->
        'cloud_policy_collector' — the report shows just the collector's
        own module name, not the full Python import path."""
        return dotted_name.rsplit(".", 1)[-1]
