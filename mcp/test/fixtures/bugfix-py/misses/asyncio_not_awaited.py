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
    asyncio.create_task(asyncio.sleep(1))
    return "done"


async def taskgroup_scheduled(tg):
    tg.create_task(asyncio.sleep(1))


def collected_for_later(acc):
    acc.append(asyncio.sleep(1))


async def deferred():
    return asyncio.sleep(1)


async def stored():
    pending = asyncio.gather(work(1))
    return await pending


# --- Written by the AUDITOR. An async generator that YIELDS the coroutine
# --- hands it to whoever consumes the generator, which is the same
# --- transfer-of-ownership the other exclusions cover. It was the only
# --- false positive left in the auditor's probe. DISCRIMINATING: delete the
# --- `yield $ANY` clause and it fires.
async def yielded():
    yield asyncio.sleep(1)


# Assignment through a subscript, and through a tuple target — both already
# covered by the `$V = $ANY` clause, recorded here so that clause has a
# near-miss per target shape rather than only the plain-name one.
async def subscript_target(store):
    store["job"] = asyncio.sleep(1)
    await store["job"]


async def tuple_target():
    a, b = asyncio.sleep(1), asyncio.sleep(2)
    await asyncio.gather(a, b)


# Handed to a scheduler that is not `asyncio.*`.
async def to_loop(loop):
    loop.run_until_complete(asyncio.sleep(1))
