""SSH authentication handler implementation."""
import asyncio
import socket
import paramiko
import logging
from typing import Optional
from datetime import datetime

from ..models import AuthResult, AuthResultStatus, Credential, Target
from . import AuthHandler, AuthHandlerFactory

logger = logging.getLogger(__name__)

@AuthHandlerFactory.register(ProtocolType.SSH, None)
class SSHAuthHandler(AuthHandler):
    """SSH authentication handler using Paramiko."""
    
    def __init__(self, target: Target):
        super().__init__(target)
        self.client: Optional[paramiko.SSHClient] = None
        self._transport: Optional[paramiko.Transport] = None
    
    async def connect(self) -> bool:
        """Establish SSH connection to the target."""
        if self.connected and self._transport and self._transport.is_active():
            return True
            
        try:
            # Create a new SSH client
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Set timeout for the connection
            timeout = 10  # Default timeout in seconds
            
            # Connect using asyncio to avoid blocking
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.client.connect(
                    hostname=self.target.host,
                    port=self.target.port,
                    timeout=timeout,
                    banner_timeout=timeout,
                    auth_timeout=timeout,
                )
            )
            
            # Get the transport for later use
            self._transport = self.client.get_transport()
            if not self._transport:
                raise Exception("Failed to establish SSH transport")
                
            self.connected = True
            return True
            
        except (paramiko.SSHException, socket.error, socket.timeout, OSError) as e:
            logger.error(f"SSH connection failed to {self.target.host}:{self.target.port}: {str(e)}")
            await self.disconnect()
            return False
    
    async def authenticate(self, credential: Credential) -> AuthResult:
        """Attempt to authenticate with the given credentials."""
        start_time = datetime.utcnow()
        
        if not self.connected and not await self.connect():
            return AuthResult(
                target=self.target,
                credential=credential,
                status=AuthResultStatus.ERROR,
                response_time=(datetime.utcnow() - start_time).total_seconds(),
                error="Failed to establish SSH connection"
            )
        
        try:
            # Try to authenticate
            transport = self.client.get_transport()
            if not transport:
                raise Exception("No active SSH transport")
                
            # Create a new transport for each authentication attempt to avoid state issues
            sock = transport.sock
            new_transport = paramiko.Transport(sock)
            new_transport.start_client()
            
            # Try to authenticate with the credentials
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: new_transport.auth_password(
                    username=credential.username,
                    password=credential.password,
                    event=None,
                    fallback=True
                )
            )
            
            response_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Check authentication result
            if result == paramiko.common.AUTH_SUCCESSFUL:
                return AuthResult(
                    target=self.target,
                    credential=credential,
                    status=AuthResultStatus.SUCCESS,
                    response_time=response_time,
                    response_data={"banner": transport.remote_version}
                )
            else:
                return AuthResult(
                    target=self.target,
                    credential=credential,
                    status=AuthResultStatus.FAILURE,
                    response_time=response_time
                )
                
        except paramiko.AuthenticationException:
            return AuthResult(
                target=self.target,
                credential=credential,
                status=AuthResultStatus.FAILURE,
                response_time=(datetime.utcnow() - start_time).total_seconds()
            )
            
        except paramiko.SSHException as e:
            error_msg = str(e).lower()
            status = AuthResultStatus.ERROR
            
            # Check for common error patterns to determine the status
            if "authentication timeout" in error_msg:
                status = AuthResultStatus.RATE_LIMITED
            elif "connection reset" in error_msg or "connection refused" in error_msg:
                # Connection issues might indicate the service is down or blocking us
                self.connected = False
                
            return AuthResult(
                target=self.target,
                credential=credential,
                status=status,
                response_time=(datetime.utcnow() - start_time).total_seconds(),
                error=str(e)
            )
            
        except Exception as e:
            logger.exception(f"Unexpected error during SSH authentication: {str(e)}")
            return AuthResult(
                target=self.target,
                credential=credential,
                status=AuthResultStatus.ERROR,
                response_time=(datetime.utcnow() - start_time).total_seconds(),
                error=f"Unexpected error: {str(e)}"
            )
            
        finally:
            # Clean up the transport we created for this attempt
            if 'new_transport' in locals() and new_transport:
                new_transport.close()
    
    async def disconnect(self):
        """Close the SSH connection."""
        try:
            if self.client:
                self.client.close()
                self.client = None
            if hasattr(self, '_transport') and self._transport:
                self._transport.close()
                self._transport = None
        except Exception as e:
            logger.warning(f"Error closing SSH connection: {str(e)}")
        finally:
            self.connected = False
