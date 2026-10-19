import json, logging, time
from fastapi import FastAPI, Request
from .config import settings
M = {"requests": 0, "errors": 0, "latency_ms_sum": 0.0}
class JsonFmt(logging.Formatter):
    def format(self, r): return json.dumps({"level": r.levelname, "msg": r.getMessage(), **getattr(r, "extra_", {})})
def setup(app: FastAPI):
    h = logging.StreamHandler(); h.setFormatter(JsonFmt()); log = logging.getLogger("lifemesh"); log.addHandler(h); log.setLevel(logging.INFO)
    @app.middleware("http")
    async def mw(request: Request, call_next):
        t = time.time()
        try: r = await call_next(request)
        except Exception: M["errors"] += 1; raise
        ms = (time.time() - t) * 1000; M["requests"] += 1; M["latency_ms_sum"] += ms; M["errors"] += r.status_code >= 500
        log.info("request", extra={"extra_": {"path": request.url.path, "status": r.status_code, "ms": round(ms, 1)}}); return r  # path only: no query strings or bodies
    @app.get("/metrics")
    def metrics(): return {**M, "avg_ms": M["latency_ms_sum"] / max(M["requests"], 1)}
    if settings.otel_endpoint:  # OpenTelemetry traces -> OTLP collector
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        tp = TracerProvider(); tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.otel_endpoint))); trace.set_tracer_provider(tp)
        FastAPIInstrumentor.instrument_app(app)
