import asyncio
from abc import ABC, abstractmethod
from loguru import logger
from pydantic import BaseModel, model_validator
from datetime import timedelta
import datetime
import aiohttp


class AsyncLoopRunner(BaseModel, ABC):
    interval: int = 10  # interval to run the main function in seconds
    running: bool = False
    name: str | None = None
    step: int = 0

    @model_validator(mode="after")
    def validate_name(self):
        if self.name is None:
            self.name = self.__class__.__name__
        return self

    @abstractmethod
    async def run_step(self):
        """Implement this method with the logic that needs to run periodically."""
        raise NotImplementedError("run_step method must be implemented")


    async def wait_for_next_execution(self, last_run_time):
        """Wait until the next execution time based on last run."""
        current_time = datetime.datetime.now(datetime.timezone.utc)
        next_run = last_run_time + timedelta(seconds=self.interval)
        wait_time = (next_run - current_time).total_seconds()
        if wait_time > 0:
            await asyncio.sleep(wait_time)
        return next_run

    async def run_loop(self):
        """Run the loop periodically."""
        last_run_time = datetime.datetime.now(datetime.timezone.utc)
        try:
            while self.running:
                next_run = await self.wait_for_next_execution(last_run_time)
                try:
                    await self.run_step()
                    self.step += 1
                    last_run_time = next_run
                except Exception as ex:
                    logger.exception(f"Error in loop iteration: {ex}")
        except asyncio.CancelledError:
            logger.info("Loop was stopped.")
        except Exception as e:
            logger.error(f"Fatal error in loop: {e}")
        finally:
            self.running = False
            # logger.info("Loop has been cleaned up.")
        logger.debug("Exiting run_loop")

    async def start(self):
        """Start the loop."""
        if self.running:
            logger.warning("Loop is already running.")
            return
        self.running = True
        # logger.debug(f"{self.name}: Starting loop with {'synchronized' if self.sync else 'non-synchronized'} mode")
        self._task = asyncio.create_task(self.run_loop())

    async def stop(self):
        """Stop the loop."""
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                logger.info("Loop task was cancelled.")