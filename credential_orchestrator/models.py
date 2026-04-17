"""Data models for the Credential Orchestrator."""
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, Field, validator
from datetime import datetime


class ProtocolType(str, Enum):
    """Supported authentication protocols."""
    SSH = "ssh"
    RDP = "rdp"
    LDAP = "ldap"
    HTTP = "http"
    HTTPS = "https"


class AuthResultStatus(str, Enum):
    """Possible authentication result statuses."""
    SUCCESS = "success"
    FAILURE = "failure"
    LOCKED = "account_locked"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"
    SKIPPED = "skipped"


class Credential(BaseModel):
    """Represents a username/password pair for authentication attempts."""
    username: str
    password: str
    domain: Optional[str] = None

    def __hash__(self):
        return hash((self.username, self.password, self.domain))


class Target(BaseModel):
    """Represents a target system for authentication attempts."""
    host: str
    port: int
    protocol: ProtocolType
    domain: Optional[str] = None
    service_name: Optional[str] = None
    is_active: bool = True
    last_checked: Optional[datetime] = None
    lockout_threshold: Optional[int] = None
    lockout_observed: bool = False
    last_lockout: Optional[datetime] = None


class AuthResult(BaseModel):
    """Result of an authentication attempt."""
    target: Target
    credential: Credential
    status: AuthResultStatus
    response_time: float  # in seconds
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: Optional[str] = None
    response_data: Optional[Dict] = None

    @validator('status')
    def validate_status(cls, v, values):
        if v == AuthResultStatus.ERROR and not values.get('error'):
            raise ValueError("Error status requires an error message")
        return v


class AttackProfile(BaseModel):
    """Configuration for a credential attack."""
    name: str
    description: str
    protocol: ProtocolType
    rate_limit: int = 10  # requests per minute
    max_attempts_per_account: int = 3
    lockout_avoidance: bool = True
    lockout_threshold: int = 5
    lockout_observation_window: int = 3600  # seconds
    delay_between_attempts: Tuple[float, float] = (1.0, 5.0)  # min, max in seconds
    stop_on_first_success: bool = False
    timeout: int = 10  # seconds

    @validator('delay_between_attempts')
    def validate_delays(cls, v):
        if len(v) != 2 or v[0] < 0 or v[1] < v[0]:
            raise ValueError("delay_between_attempts must be a tuple of (min, max) where min <= max and both >= 0")
        return v


class AttackStats(BaseModel):
    """Statistics for an attack run."""
    start_time: datetime = Field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    total_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0
    locked_accounts: int = 0
    rate_limited: int = 0
    errors: int = 0
    credentials_tested: int = 0
    targets_tested: int = 0
    avg_response_time: float = 0.0

    def update_stats(self, result: AuthResult):
        """Update statistics based on authentication result."""
        self.total_attempts += 1
        self.avg_response_time = (
            (self.avg_response_time * (self.total_attempts - 1) + result.response_time) 
            / self.total_attempts
        )

        if result.status == AuthResultStatus.SUCCESS:
            self.successful_attempts += 1
        elif result.status == AuthResultStatus.FAILURE:
            self.failed_attempts += 1
        elif result.status == AuthResultStatus.LOCKED:
            self.locked_accounts += 1
        elif result.status == AuthResultStatus.RATE_LIMITED:
            self.rate_limited += 1
        elif result.status == AuthResultStatus.ERROR:
            self.errors += 1

    def finalize(self):
        """Mark the end of the attack and finalize stats."""
        self.end_time = datetime.utcnow()

    @property
    def duration(self) -> float:
        """Return the duration of the attack in seconds."""
        end = self.end_time or datetime.utcnow()
        return (end - self.start_time).total_seconds()

    @property
    def success_rate(self) -> float:
        """Return the success rate as a percentage."""
        if self.total_attempts == 0:
            return 0.0
        return (self.successful_attempts / self.total_attempts) * 100
