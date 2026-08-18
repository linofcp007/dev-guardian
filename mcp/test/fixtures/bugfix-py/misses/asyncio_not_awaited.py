import asyncio


async def throttle():
    await asyncio.sleep(1)
    return "done"


async def fan_out(items):
    await asyncio.gather(*[work(i) for i in items])
    return "done"


async def join_all(tasks):
    await asyncio.wait(tasks)
    return "done"


async def bounded(task):
    return await asyncio.wait_for(task, timeout=5)


async def scheduled():
    asyncio.create_task(work(1))
    return "done"


async def deferred():
    return asyncio.sleep(1)


async def stored():
    pending = asyncio.gather(work(1))
    return await pending
