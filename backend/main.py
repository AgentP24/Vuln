"""
VulnGuard AI - Main Application
Multi-Agent Vulnerability Management System
"""
import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog

from config import get_settings
from api import (
    vulnerabilities_router,
    approvals_router,
    executions_router,
    agents_router,
    playbooks_router,
    dashboard_router
)

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()
settings = get_settings()

# Global agent instances
agents: Dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.
    Initializes agents and background tasks on startup,
    cleans up on shutdown.
    """
    logger.info("Starting VulnGuard AI", version=settings.app_version)

    # Initialize agents (would be done with actual dependencies in production)
    try:
        # Import agents
        from agents import (
            DiscoveryAgent, AssessmentAgent, ApprovalAgent,
            RemediationAgent, ValidationAgent
        )
        from models import MaintenanceWindow, Playbook

        # Mock dependencies for MVP
        scanner_clients = {}
        playbook_registry = {
            "pb-tls-hardening": Playbook(
                id="pb-tls-hardening",
                name="TLS/SSL Hardening",
                description="Disable deprecated TLS versions",
                target_platforms=["Linux", "Windows", "server"],
                requires_restart=True,
                estimated_duration=15,
                success_rate=0.94
            ),
            "pb-ssh-hardening": Playbook(
                id="pb-ssh-hardening",
                name="SSH Hardening",
                description="Secure SSH configuration",
                target_platforms=["Linux", "server"],
                requires_restart=False,
                estimated_duration=5,
                success_rate=0.96
            )
        }
        maintenance_windows = []

        # Initialize agents
        agents["discovery"] = DiscoveryAgent(scanner_clients=scanner_clients)
        agents["assessment"] = AssessmentAgent(playbook_registry=playbook_registry)
        agents["approval"] = ApprovalAgent(maintenance_windows=maintenance_windows)
        agents["remediation"] = RemediationAgent()
        agents["validation"] = ValidationAgent(scanner_clients=scanner_clients)

        logger.info("All agents initialized successfully")

    except Exception as e:
        logger.error("Failed to initialize agents", error=str(e))

    # Start background tasks (discovery polling, etc.)
    # In production, would use APScheduler or Celery
    # asyncio.create_task(discovery_polling_task())

    yield

    # Cleanup
    logger.info("Shutting down VulnGuard AI")

    # Close agent connections
    for agent_name, agent in agents.items():
        try:
            if hasattr(agent, 'close'):
                await agent.close()
        except Exception as e:
            logger.warning(f"Error closing {agent_name}", error=str(e))


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description="""
    # VulnGuard AI - Multi-Agent Vulnerability Management System

    A sophisticated multi-agent system for enterprise vulnerability management
    with human-in-the-loop approval workflows and strict production guardrails.

    ## Key Features

    - **Discovery Agent**: Continuously polls Qualys, Tenable, Rapid7, and Guardium
    - **Assessment Agent**: Calculates business risk and recommends remediation
    - **Approval Agent**: Manages human approval workflow with strict guardrails
    - **Remediation Agent**: Executes fixes via Ansible with rollback capability
    - **Validation Agent**: Verifies fixes and maintains feedback loop

    ## Guardrails

    - Tier 1 assets ALWAYS require human approval
    - No production changes during business hours
    - Mandatory check mode before apply for Tier 1/2
    - Automatic rollback on failure

    ## Architecture

    ```
    Discovery → Assessment → Approval → Remediation → Validation
        ↑                                                  │
        └──────────── Feedback Loop ───────────────────────┘
    ```
    """,
    version=settings.app_version,
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception", path=request.url.path, error=str(exc))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


# Include routers
app.include_router(vulnerabilities_router, prefix=settings.api_prefix)
app.include_router(approvals_router, prefix=settings.api_prefix)
app.include_router(executions_router, prefix=settings.api_prefix)
app.include_router(agents_router, prefix=settings.api_prefix)
app.include_router(playbooks_router, prefix=settings.api_prefix)
app.include_router(dashboard_router, prefix=settings.api_prefix)


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": settings.app_version,
        "agents": {
            name: agent.state.status.value
            for name, agent in agents.items()
        } if agents else {}
    }


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/health",
        "api_prefix": settings.api_prefix
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug
    )
