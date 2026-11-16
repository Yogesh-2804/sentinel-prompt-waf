import logging
import json
import sys
from datetime import datetime
from app.core.config import settings


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Attach extra fields if present
        if hasattr(record, "client_ip"):
            log_obj["client_ip"] = record.client_ip
        if hasattr(record, "user_id"):
            log_obj["user_id"] = record.user_id
        if hasattr(record, "threat_score"):
            log_obj["threat_score"] = record.threat_score
        if hasattr(record, "execution_time_ms"):
            log_obj["execution_time_ms"] = record.execution_time_ms
        if hasattr(record, "event_type"):
            log_obj["event_type"] = record.event_type

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("sentinel_waf")
    logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
    
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        
    return logger


logger = setup_logger()
