"""Decoder progress is distinct from source-byte progress and capture completeness."""
from __future__ import annotations

from datetime import datetime, timezone
import time


class InspectionFreshness:
    def __init__(self):
        self.population = None
        self.progress_time = None
        self.progress_utc = None
        self.generation = None

    def observe(self, events, total, *, finalized, generation):
        now = time.monotonic()
        utc = datetime.now(timezone.utc).isoformat()
        reset = self.generation != generation or (
            self.population is not None and total < self.population)
        added = None if self.population is None or reset else total-self.population
        if (self.population is None or reset) and total:
            self.progress_time, self.progress_utc = now, utc
        elif added:
            self.progress_time, self.progress_utc = now, utc
        elif reset:
            self.progress_time = self.progress_utc = None
        self.population, self.generation = total, generation
        latest = max((e['ts'] for e in events), default=None)
        return {
            'scope': 'latest-ingested-observations',
            'read_at_utc': utc,
            'newly_visible_observations': added,
            'comparison_reset': reset,
            'last_progress_at_utc': self.progress_utc,
            'seconds_since_progress': (round(max(0, now-self.progress_time), 3)
                                       if self.progress_time is not None else None),
            # Native timestamps are not UTC or JavaScript-safe integers.
            'latest_event_timestamp_ns': str(latest) if latest is not None else None,
            'timestamp_clock': 'recording-clock',
            'pending_events_possible': not finalized,
            'proves_capture_complete': False,
        }
