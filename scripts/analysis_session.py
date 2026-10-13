"""Scan-scoped, thread-safe reuse of immutable completed call graphs."""
import threading


class AnalysisSession:
    def __init__(self, *, freeze_sources=False):
        self.freeze_sources = freeze_sources
        self._snapshots = {}
        self._snapshot_lock = threading.Lock()
        self._snapshot_hits = 0
        self._graphs = {}
        self._lock = threading.Lock()
        self.graph_builds = 0
        self.graph_hits = 0
        self._references = {}
        self._reference_lock = threading.Lock()

    def graph(self, key, build):
        # Do not publish a half-built graph or cache failed construction.
        with self._lock:
            if key in self._graphs:
                self.graph_hits += 1
                return self._graphs[key]
            graph = build()
            self._graphs[key] = graph
            self.graph_builds += 1
            return graph

    def metrics(self):
        with self._lock:
            metrics = {"graph_builds": self.graph_builds, "graph_hits": self.graph_hits}
        if self.freeze_sources:
            with self._snapshot_lock:
                metrics.update(source_captures=len(self._snapshots), source_snapshot_hits=self._snapshot_hits,
                               source_files=sum(len(s.files) for s in self._snapshots.values()),
                               source_bytes=sum(len(raw) for s in self._snapshots.values() for _, raw in s.files))
        return metrics

    def source_snapshot(self, directory, include_tests=False):
        from pathlib import Path
        from scripts.python_graph import capture_sources
        if not self.freeze_sources:
            return capture_sources(directory, include_tests)
        key = (Path(directory).resolve(), bool(include_tests))
        with self._snapshot_lock:
            if key in self._snapshots:
                self._snapshot_hits += 1
            else:
                # Failed reads are not published or cached.
                self._snapshots[key] = capture_sources(*key)
            return self._snapshots[key]

    def reference(self, key, fetch):
        """Reuse successful reference reads within one scan; retry failures."""
        with self._reference_lock:
            if key not in self._references:
                self._references[key] = fetch()
            return self._references[key]
