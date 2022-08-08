# -*- coding: utf-8 -*-
"""
   Description:
        -
        -
"""
import asyncio
import functools


def sync_task(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.get_event_loop().run_until_complete(f(*args, **kwargs))

    return wrapper
