""
Authentication handlers for different protocols.
"""
from typing import Dict, Type, Optional
from ..models import ProtocolType, AuthResult, Credential, Target
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)

class AuthHandler(ABC):
    """Base class for authentication handlers."""
    
    def __init__(self, target: Target):
        self.target = target
        self.connected = False
        
    @abstractmethod
    async def authenticate(self, credential: Credential) -> AuthResult:
        """Attempt to authenticate with the given credentials."""
        pass
    
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to the target."""
        pass
    
    @abstractmethod
    async def disconnect(self):
        """Close the connection to the target."""
        pass
    
    async def __aenter__(self):
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()


class AuthHandlerFactory:
    """Factory for creating protocol-specific authentication handlers."""
    _handlers: Dict[ProtocolType, Type[AuthHandler]] = {}
    
    @classmethod
    def register(cls, protocol: ProtocolType, handler: Type[AuthHandler]):
        """Register a new handler for a protocol."""
        cls._handlers[protocol] = handler
        return handler
    
    @classmethod
    def get_handler(cls, protocol: ProtocolType, target: Target) -> Optional[AuthHandler]:
        """Get a handler instance for the given protocol and target."""
        handler_class = cls._handlers.get(protocol)
        if not handler_class:
            logger.error(f"No handler registered for protocol: {protocol}")
            return None
        return handler_class(target)
    
    @classmethod
    def get_available_protocols(cls) -> list:
        """Get a list of supported protocols."""
        return list(cls._handlers.keys())
