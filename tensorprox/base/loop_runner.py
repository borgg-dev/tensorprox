"""
Async loop runner for background tasks.

Provides a reusable base class for running periodic async tasks
like health monitoring, weight setting, and scoring.
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Optional
import traceback

from pydantic import BaseModel, Field
from loguru import logger


class AsyncLoopRunner(BaseModel, ABC):
    """
    Base class for async background task runners.

    Subclasses implement run_step() which is called at the
    specified interval. Handles errors gracefully and provides
    lifecycle management.
    """

    model_config = {"arbitrary_types_allowed": True}

    # Configuration
    interval: int = Field(
        default=10,
        description="Run interval in seconds"
    )
    name: str = Field(
        default="loop_runner",
        description="Name for logging"
    )

    # State
    running: bool = Field(default=False, description="Is loop running")
    step: int = Field(default=0, description="Current step count")

    # Internal
    _task: Optional[asyncio.Task] = None

    @abstractmethod
    async def run_step(self) -> None:
        """
        Execute one step of the loop.

        Subclasses must implement this method with their
        specific logic. Errors are caught and logged.
        """
        pass

    async def start(self) -> None:
        """Start the background loop."""
        if self.running:
            logger.warning(f"{self.name}: Already running")
            return

        self.running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info(f"{self.name}: Started with interval {self.interval}s")

    async def stop(self) -> None:
        """Stop the background loop."""
        if not self.running:
            return

        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info(f"{self.name}: Stopped after {self.step} steps")

    async def _run_loop(self) -> None:
        """Internal loop that calls run_step at intervals."""
        while self.running:
            try:
                await self.run_step()
                self.step += 1
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(
                    f"{self.name}: Error in step {self.step}: {e}\n"
                    f"{traceback.format_exc()}"
                )

            # Wait for next interval
            try:
                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:
                break

    async def run_once(self) -> None:
        """Run a single step (useful for testing)."""
        try:
            await self.run_step()
            self.step += 1
        except Exception as e:
            logger.error(f"{self.name}: Error in run_once: {e}")
            raise

    def reset(self) -> None:
        """Reset step counter."""
        self.step = 0


class IntervalRunner(AsyncLoopRunner):
    """
    Generic interval runner with callback support.

    Allows running any async function at a fixed interval
    without subclassing.
    """

    callback: Optional[callable] = None

    async def run_step(self) -> None:
        """Execute the callback if set."""
        if self.callback:
            await self.callback()


class ConditionalRunner(AsyncLoopRunner):
    """
    Runner that checks a condition before each step.

    Useful for tasks that should only run when certain
    conditions are met (e.g., only set weights when needed).
    """

    @abstractmethod
    async def should_run(self) -> bool:
        """Check if the step should run."""
        pass

    async def _run_loop(self) -> None:
        """Loop that checks condition before running."""
        while self.running:
            try:
                if await self.should_run():
                    await self.run_step()
                    self.step += 1
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(
                    f"{self.name}: Error in step {self.step}: {e}\n"
                    f"{traceback.format_exc()}"
                )

            try:
                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:
                break
