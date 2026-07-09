import structlog


def configure_logging(log_level: str = "INFO") -> None:
    # Pure-structlog setup (PrintLoggerFactory, not stdlib logging) — deliberately
    # uses structlog.processors.add_log_level rather than structlog.stdlib.add_log_level
    # / add_logger_name, which assume a stdlib logging.Logger (with a `.name`
    # attribute) and raise AttributeError against a plain PrintLogger.
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(__import__("logging"), log_level, 20)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
    )


def get_logger(name: str = "agent") -> structlog.BoundLogger:
    return structlog.get_logger(name)
