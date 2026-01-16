from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api.v1 import calculate, industries, actors, admin, companies, exploit_db
from app.utils.logging import setup_logging
from app.utils.security import get_rate_limiter
from config import settings
import time
import redis.asyncio as redis

logger = setup_logging()

app = FastAPI(
    title="ATLAS API",
    description="Adversary Technique & Landscape Analysis by Sector - API for calculating threat actor groups by industry",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development (restrict in production)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Skip rate limiting for health checks and docs
    if request.url.path in ["/health", "/docs", "/openapi.json", "/redoc"]:
        return await call_next(request)
    
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    
    # Check if admin endpoint
    is_admin = request.url.path.startswith("/api/v1/admin")
    limit = settings.admin_rate_limit_per_hour if is_admin else settings.api_rate_limit_per_hour
    
    try:
        # Get rate limiter
        rate_limiter = await get_rate_limiter()
        
        # Check rate limit
        key = f"rate_limit:{client_ip}:{request.url.path}"
        is_allowed, remaining = await rate_limiter.check_rate_limit(key, limit, 3600)
        
        if not is_allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": f"Rate limit exceeded. Limit: {limit} requests per hour.",
                    "retry_after": 3600
                },
                headers={"Retry-After": "3600"}
            )
        
        # Add rate limit headers
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining) if remaining else "unknown"
        
        return response
    except Exception as e:
        # If rate limiting fails, allow request (fail open)
        logger.warning(f"Rate limiting error: {e}")
        return await call_next(request)


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


# Include routers
app.include_router(calculate.router, prefix="/api/v1", tags=["calculate"])
app.include_router(industries.router, prefix="/api/v1", tags=["industries"])
app.include_router(actors.router, prefix="/api/v1", tags=["actors"])
app.include_router(companies.router, prefix="/api/v1", tags=["companies"])
app.include_router(exploit_db.router, prefix="/api/v1", tags=["exploit-db"])
app.include_router(admin.router, prefix="/api/v1", tags=["admin"])


@app.get("/")
async def root():
    return {
        "message": "ATLAS API - Adversary Technique & Landscape Analysis by Sector",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health")
async def health():
    """Basic health check endpoint"""
    return {"status": "healthy"}


@app.get("/health/detailed")
async def health_detailed():
    """Detailed health check with database and Redis connectivity"""
    health_status = {
        "status": "healthy",
        "timestamp": time.time(),
        "checks": {}
    }
    
    # Check database
    try:
        from app.db import AsyncSessionLocal
        from sqlalchemy import text
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
        health_status["checks"]["database"] = "healthy"
    except Exception as e:
        health_status["status"] = "degraded"
        health_status["checks"]["database"] = f"unhealthy: {str(e)}"
    
    # Check Redis
    try:
        redis_client = redis.from_url(settings.redis_url, decode_responses=True)
        await redis_client.ping()
        await redis_client.aclose()
        health_status["checks"]["redis"] = "healthy"
    except Exception as e:
        health_status["status"] = "degraded"
        health_status["checks"]["redis"] = f"unhealthy: {str(e)}"
    
    status_code = 200 if health_status["status"] == "healthy" else 503
    return JSONResponse(content=health_status, status_code=status_code)


@app.get("/health/ready")
async def health_ready():
    """Kubernetes/Docker readiness probe - checks if service is ready to accept traffic"""
    try:
        from app.db import AsyncSessionLocal
        from sqlalchemy import text
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={"status": "not ready", "error": str(e)}
        )


@app.get("/health/live")
async def health_live():
    """Kubernetes/Docker liveness probe - checks if service is alive"""
    return {"status": "alive"}


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with structured responses"""
    logger.warning(
        f"HTTP {exc.status_code} on {request.method} {request.url.path}: {exc.detail}",
        extra={
            "path": request.url.path,
            "method": request.method,
            "status_code": exc.status_code,
            "client_ip": request.client.host if request.client else "unknown"
        }
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "error_type": "http_exception",
            "path": request.url.path
        }
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler with detailed logging and structured responses"""
    import traceback
    import uuid
    
    # Generate error ID for tracking
    error_id = str(uuid.uuid4())[:8]
    
    # Log full exception details
    logger.error(
        f"Unhandled exception on {request.method} {request.url.path}: {exc}",
        exc_info=True,
        extra={
            "error_id": error_id,
            "path": request.url.path,
            "method": request.method,
            "client_ip": request.client.host if request.client else "unknown",
            "traceback": traceback.format_exc()
        }
    )
    
    # Return structured error response (don't leak internal details in production)
    error_detail = "Internal server error"
    # In production, don't expose exception details
    # In development, you could check an environment variable
    
    return JSONResponse(
        status_code=500,
        content={
            "detail": error_detail,
            "error_type": "internal_server_error",
            "error_id": error_id,
            "path": request.url.path,
            "message": "An unexpected error occurred. Please contact support with the error_id."
        }
    )
