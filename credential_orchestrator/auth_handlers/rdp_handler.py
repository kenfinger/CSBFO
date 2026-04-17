""RDP authentication handler implementation."""
import asyncio
import logging
from typing import Optional, Dict, Any
from datetime import datetime

import rdp

from ..models import AuthResult, AuthResultStatus, Credential, Target, ProtocolType
from . import AuthHandler, AuthHandlerFactory

logger = logging.getLogger(__name__)

@AuthHandlerFactory.register(ProtocolType.RDP, None)
class RDPAuthHandler(AuthHandler):
    """RDP authentication handler using the rdp library."""
    
    def __init__(self, target: Target):
        super().__init__(target)
        self.client = None
        self._connected = False
    
    async def connect(self) -> bool:
        """Initialize RDP client (connection is established during auth)."""
        # For RDP, we'll establish the connection during authentication
        return True
    
    async def authenticate(self, credential: Credential) -> AuthResult:
        """Attempt to authenticate with the given credentials."""
        start_time = datetime.utcnow()
        
        # Format the username with domain if provided
        username = credential.username
        if credential.domain:
            username = f"{credential.domain}\\{credential.username}"
        
        try:
            # Create RDP client configuration
            rdp_client = rdp.RdpClient(
                server=f"{self.target.host}:{self.target.port}",
                username=username,
                password=credential.password,
                domain=credential.domain or "",
                timeout=10,  # seconds
                enable_credssp=True,
                disable_credssp=False
            )
            
            # Try to connect and authenticate
            connected = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: rdp_client.connect()
            )
            
            response_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Check if authentication was successful
            if connected:
                result = AuthResult(
                    target=self.target,
                    credential=credential,
                    status=AuthResultStatus.SUCCESS,
                    response_time=response_time,
                    response_data={
                        "protocol": "RDP",
                        "server_name": self.target.host,
                        "port": self.target.port
                    }
                )
            else:
                result = AuthResult(
                    target=self.target,
                    credential=credential,
                    status=AuthResultStatus.FAILURE,
                    response_time=response_time
                )
            
            # Disconnect if connected
            if connected:
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    rdp_client.disconnect
                )
                
            return result
            
        except rdp.RdpError as e:
            error_msg = str(e).lower()
            status = AuthResultStatus.ERROR
            
            # Map common RDP errors to our statuses
            if "credssp" in error_msg or "ssl" in error_msg:
                status = AuthResultStatus.ERROR
            elif "timeout" in error_msg:
                status = AuthResultStatus.RATE_LIMITED
            elif "account" in error_msg and "locked" in error_msg:
                status = AuthResultStatus.LOCKED
            elif "authentication" in error_msg:
                status = AuthResultStatus.FAILURE
            
            return AuthResult(
                target=self.target,
                credential=credential,
                status=status,
                response_time=(datetime.utcnow() - start_time).total_seconds(),
                error=f"RDP error: {str(e)}"
            )
            
        except Exception as e:
            logger.exception(f"Unexpected error during RDP authentication: {str(e)}")
            return AuthResult(
                target=self.target,
                credential=credential,
                status=AuthResultStatus.ERROR,
                response_time=(datetime.utcnow() - start_time).total_seconds(),
                error=f"Unexpected error: {str(e)}"
            )
    
    async def disconnect(self):
        """Clean up RDP client."""
        # No explicit cleanup needed as we handle it in the authenticate method
        self._connected = False
        self.client = None
