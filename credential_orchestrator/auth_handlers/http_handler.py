""HTTP/HTTPS authentication handler implementation."""
import asyncio
import aiohttp
import logging
from typing import Optional, Dict, Any
from datetime import datetime

from ..models import AuthResult, AuthResultStatus, Credential, Target, ProtocolType
from . import AuthHandler, AuthHandlerFactory

logger = logging.getLogger(__name__)

@AuthHandlerFactory.register(ProtocolType.HTTP, None)
@AuthHandlerFactory.register(ProtocolType.HTTPS, None)
class HTTPAuthHandler(AuthHandler):
    """HTTP/HTTPS authentication handler using aiohttp."""
    
    def __init__(self, target: Target):
        super().__init__(target)
        self.session: Optional[aiohttp.ClientSession] = None
        self._base_url = f"{self.target.protocol}://{self.target.host}"
        if self.target.port not in (80, 443):
            self._base_url += f":{self.target.port}"
    
    async def connect(self) -> bool:
        """Initialize HTTP session."""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=10)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return True
    
    async def authenticate(self, credential: Credential) -> AuthResult:
        """Attempt to authenticate with the given credentials using HTTP Basic Auth."""
        start_time = datetime.utcnow()
        
        if not await self.connect():
            return AuthResult(
                target=self.target,
                credential=credential,
                status=AuthResultStatus.ERROR,
                response_time=(datetime.utcnow() - start_time).total_seconds(),
                error="Failed to initialize HTTP session"
            )
        
        auth_url = self._base_url
        if self.target.service_name:
            auth_url = f"{self._base_url}/{self.target.service_name.lstrip('/')}"
        
        try:
            async with self.session.get(
                auth_url,
                auth=aiohttp.BasicAuth(credential.username, credential.password),
                allow_redirects=True,
                ssl=False
            ) as response:
                response_time = (datetime.utcnow() - start_time).total_seconds()
                
                # Check for common authentication patterns
                if response.status == 200:
                    return AuthResult(
                        target=self.target,
                        credential=credential,
                        status=AuthResultStatus.SUCCESS,
                        response_time=response_time,
                        response_data={
                            "status_code": response.status,
                            "headers": dict(response.headers)
                        }
                    )
                elif response.status in (401, 403):
                    return AuthResult(
                        target=self.target,
                        credential=credential,
                        status=AuthResultStatus.FAILURE,
                        response_time=response_time,
                        response_data={"status_code": response.status}
                    )
                elif response.status == 429:  # Too Many Requests
                    return AuthResult(
                        target=self.target,
                        credential=credential,
                        status=AuthResultStatus.RATE_LIMITED,
                        response_time=response_time,
                        response_data={"status_code": response.status}
                    )
                else:
                    return AuthResult(
                        target=self.target,
                        credential=credential,
                        status=AuthResultStatus.ERROR,
                        response_time=response_time,
                        error=f"Unexpected status code: {response.status}",
                        response_data={"status_code": response.status}
                    )
                    
        except asyncio.TimeoutError:
            return AuthResult(
                target=self.target,
                credential=credential,
                status=AuthResultStatus.RATE_LIMITED,
                response_time=(datetime.utcnow() - start_time).total_seconds(),
                error="Request timed out"
            )
            
        except aiohttp.ClientError as e:
            return AuthResult(
                target=self.target,
                credential=credential,
                status=AuthResultStatus.ERROR,
                response_time=(datetime.utcnow() - start_time).total_seconds(),
                error=f"HTTP client error: {str(e)}"
            )
            
        except Exception as e:
            logger.exception(f"Unexpected error during HTTP authentication: {str(e)}")
            return AuthResult(
                target=self.target,
                credential=credential,
                status=AuthResultStatus.ERROR,
                response_time=(datetime.utcnow() - start_time).total_seconds(),
                error=f"Unexpected error: {str(e)}"
            )
    
    async def disconnect(self):
        """Close the HTTP session."""
        try:
            if self.session and not self.session.closed:
                await self.session.close()
        except Exception as e:
            logger.warning(f"Error closing HTTP session: {str(e)}")
        finally:
            self.connected = False
