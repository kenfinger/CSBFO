""LDAP authentication handler implementation."""
import asyncio
import logging
import ldap3
from typing import Optional, Dict, Any
from datetime import datetime

from ..models import AuthResult, AuthResultStatus, Credential, Target, ProtocolType
from . import AuthHandler, AuthHandlerFactory

logger = logging.getLogger(__name__)

@AuthHandlerFactory.register(ProtocolType.LDAP, None)
class LDAPAuthHandler(AuthHandler):
    """LDAP authentication handler using python-ldap."""
    
    def __init__(self, target: Target):
        super().__init__(target)
        self.server: Optional[ldap3.Server] = None
        self.connection: Optional[ldap3.Connection] = None
        self._base_dn: Optional[str] = None
    
    async def connect(self) -> bool:
        """Establish LDAP connection to the target."""
        if self.connected and self.connection and self.connection.bound:
            return True
            
        try:
            # Create server object
            use_ssl = self.target.protocol == ProtocolType.LDAPS
            self.server = ldap3.Server(
                host=self.target.host,
                port=self.target.port,
                use_ssl=use_ssl,
                get_info=ldap3.ALL
            )
            
            # Create connection with anonymous bind to get base DN if not provided
            self.connection = ldap3.Connection(
                self.server,
                auto_bind=ldap3.AUTO_BIND_NO_TLS,
                receive_timeout=10
            )
            
            # If we have a service name, use it as the base DN
            if self.target.service_name:
                self._base_dn = self.target.service_name
            else:
                # Try to get the defaultNamingContext as base DN if not provided
                if not self.server.info:
                    raise Exception("Could not retrieve server info")
                    
                naming_contexts = self.server.info.other.get('defaultNamingContext')
                if naming_contexts:
                    self._base_dn = naming_contexts[0]
                else:
                    raise Exception("Could not determine base DN. Please provide it in the target service_name field.")
            
            self.connected = True
            return True
            
        except Exception as e:
            logger.error(f"LDAP connection failed to {self.target.host}:{self.target.port}: {str(e)}")
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
                error="Failed to establish LDAP connection"
            )
        
        try:
            # Format the user DN
            if '@' in credential.username:
                # Assume UPN format (user@domain.com)
                user_dn = credential.username
            elif '\\' in credential.username:
                # Assume NT format (DOMAIN\user)
                domain_part, username_part = credential.username.split('\\', 1)
                user_dn = f"{username_part}@{domain_part}"
            else:
                # Try to construct DN using the base DN
                user_dn = f"CN={credential.username},{self._base_dn}"
            
            # Create a new connection for the authentication attempt
            conn = ldap3.Connection(
                self.server,
                user=user_dn,
                password=credential.password,
                auto_bind=True,
                receive_timeout=10
            )
            
            response_time = (datetime.utcnow() - start_time).total_seconds()
            
            if conn.bound:
                # Authentication successful
                result = AuthResult(
                    target=self.target,
                    credential=credential,
                    status=AuthResultStatus.SUCCESS,
                    response_time=response_time,
                    response_data={
                        "user_dn": user_dn,
                        "server_info": str(self.server.info) if self.server else None
                    }
                )
            else:
                # Authentication failed
                result = AuthResult(
                    target=self.target,
                    credential=credential,
                    status=AuthResultStatus.FAILURE,
                    response_time=response_time
                )
            
            # Close the connection we created for this attempt
            conn.unbind()
            return result
            
        except ldap3.core.exceptions.LDAPBindError as e:
            error_msg = str(e).lower()
            status = AuthResultStatus.FAILURE
            
            if "invalid credentials" in error_msg:
                status = AuthResultStatus.FAILURE
            elif "account locked" in error_msg or "password expired" in error_msg:
                status = AuthResultStatus.LOCKED
            elif "timeout" in error_msg:
                status = AuthResultStatus.RATE_LIMITED
            
            return AuthResult(
                target=self.target,
                credential=credential,
                status=status,
                response_time=(datetime.utcnow() - start_time).total_seconds(),
                error=str(e)
            )
            
        except ldap3.core.exceptions.LDAPSocketReceiveError as e:
            self.connected = False
            return AuthResult(
                target=self.target,
                credential=credential,
                status=AuthResultStatus.ERROR,
                response_time=(datetime.utcnow() - start_time).total_seconds(),
                error=f"LDAP socket error: {str(e)}"
            )
            
        except Exception as e:
            logger.exception(f"Unexpected error during LDAP authentication: {str(e)}")
            return AuthResult(
                target=self.target,
                credential=credential,
                status=AuthResultStatus.ERROR,
                response_time=(datetime.utcnow() - start_time).total_seconds(),
                error=f"Unexpected error: {str(e)}"
            )
    
    async def disconnect(self):
        """Close the LDAP connection."""
        try:
            if self.connection and not self.connection.closed:
                self.connection.unbind()
        except Exception as e:
            logger.warning(f"Error closing LDAP connection: {str(e)}")
        finally:
            self.connection = None
            self.server = None
            self.connected = False
