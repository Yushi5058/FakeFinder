import time
import logging

logger = logging.getLogger(__name__)


class PipelineBenchmarkMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start = time.perf_counter()
        response = self.get_response(request)
        elapsed = time.perf_counter() - start
        logger.info(f"[Benchmark] {request.method} {request.path} — {elapsed:.3f}s")
        return response