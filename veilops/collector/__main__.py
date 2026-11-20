"""python -m veilops.collector --config collector.yaml"""
from __future__ import annotations

import argparse
import asyncio
import logging
import socket

import uvicorn

from .config import CollectorConfig
from .contracts import SourceBus
from .pipeline.rawstore import RawStore
from .pipeline.runner import Pipeline
from .sources.base import Source
from .sources.stream import StreamMapper, StreamSource
from .ui.app import UIContext, create_app

log = logging.getLogger("veilops")


def build_sources(cfg: CollectorConfig) -> dict[str, Source]:
    s = cfg.sources or {}
    out: dict[str, Source] = {}
    st = s.get("stream")
    mapper = StreamMapper.from_file((st or {}).get("map_file"), cfg.source_tz)
    if mapper.tenant_filter is None:
        mapper.tenant_filter = (st or {}).get("tenant_filter", cfg.tenant_id)
    if st and st.get("enabled", True):
        out["stream"] = StreamSource(st, mapper)
    for extra in s.get("extra_streams") or []:          # e.g. the remediation sandbox's /metrics
        if extra.get("enabled", True):
            em = StreamMapper.from_file(extra.get("map_file"), cfg.source_tz)
            em.tenant_filter = extra.get("tenant_filter", cfg.tenant_id)
            out[extra.get("name", f"stream-{len(out)}")] = StreamSource(extra, em)
    if s.get("sim", {}).get("enabled"):
        from .sources.simsource import SimSource
        out["sim"] = SimSource(s["sim"], cfg.tenant_id, cfg.source_tz, mapper)
    if s.get("host", {}).get("enabled", False):
        from .sources.host import HostSource
        out["host"] = HostSource(s["host"], cfg.source_tz)
    if s.get("probes", {}).get("enabled", False):
        from .sources.probes import ProbeSource
        out["probes"] = ProbeSource(s["probes"], cfg.source_tz)
    if s.get("syslog", {}).get("enabled", False):
        from .sources.syslog import SyslogSource
        out["syslog"] = SyslogSource(s["syslog"], cfg.source_tz, socket.gethostname())
    for name, src in out.items():
        src.name = src.status.name = name
    return out


async def amain(cfg: CollectorConfig) -> None:
    store = RawStore(cfg.db_path)
    await store.open()
    bus = SourceBus()
    pipeline = Pipeline(cfg, bus, store)
    sources = build_sources(cfg)
    for name, src in sources.items():
        bus.status[name] = src.status
    ctx = UIContext(cfg, pipeline, store, sources)
    app = create_app(ctx)

    tasks = [asyncio.create_task(src.supervise(pipeline.ingest), name=f"src:{n}") for n, src in sources.items()]
    tasks += [asyncio.create_task(pipeline.flusher()), asyncio.create_task(pipeline.janitor())]
    from .topology import TopologyWatcher
    topo = TopologyWatcher(bus, cfg.topology_file, use_sim="sim" in sources)
    topo.refresh()
    ctx.topology_watcher = topo
    tasks.append(asyncio.create_task(topo.run()))
    if cfg.downstream == "privacy":
        # Member B: from veilops.collector.privacy.stage import run_privacy_stage
        from .privacy.stage import run_privacy_stage  # type: ignore[import-not-found]
        tasks.append(asyncio.create_task(run_privacy_stage(cfg, bus, store, ctx, app)))
    else:
        tasks.append(asyncio.create_task(pipeline.drain_without_downstream()))
    server = uvicorn.Server(uvicorn.Config(app, host=cfg.ui_host, port=cfg.ui_port, log_level="warning"))
    log.info("collector %s tenant %s region %s; UI http://%s:%s; sources=%s", cfg.collector_id, cfg.tenant_id,
             cfg.region, cfg.ui_host, cfg.ui_port, list(sources))
    try:
        await server.serve()
    finally:
        for t in tasks:
            t.cancel()
        await store.close()


def main() -> None:
    p = argparse.ArgumentParser(prog="veilops-collector")
    p.add_argument("--config", default="veilops/collector/collector.example.yaml")
    p.add_argument("--port", type=int)
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    cfg = CollectorConfig.load(a.config)
    if a.port:
        cfg.ui_port = a.port
    asyncio.run(amain(cfg))


if __name__ == "__main__":
    main()
