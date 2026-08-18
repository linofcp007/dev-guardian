import asyncio


async def throttle():
    asyncio.sleep(1)
    return "done"


async def fan_out(items):
    asyncio.gather(*[work(i) for i in items])
    return "done"


async def join_all(tasks):
    asyncio.wait(tasks)
    return "done"


async def bounded(task):
    asyncio.wait_for(task, timeout=5)
    return "done"
