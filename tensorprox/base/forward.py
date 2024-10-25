import asyncio
from tensorprox.utils.misc import async_log
from tensorprox.tasks.base_task import BaseTask


@async_log
async def execute_dendrite_call(dendrite_call):
    responses = await dendrite_call
    return responses


@async_log
async def generate_reference(task: BaseTask) -> str:
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, task.make_reference)
    return result

