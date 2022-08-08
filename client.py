# -*- coding: utf-8 -*-
"""
   Description:
        -
        -
"""
import aiohttp
import requests
import sentry_sdk
from pydash import get


class AsyncClient:
    def __init__(self, host: str, headers: dict = {}):
        self.host = host
        self.headers = headers
        pass

    async def post(self, url, data, **kwargs):
        async with aiohttp.ClientSession() as session:
            kwargs['headers'] = {
                **get(kwargs, 'headers', {}),
                **self.headers
            }
            return await session.post(f'{self.host}{url}', json=data, **kwargs)

    async def get(self, url, params, **kwargs):
        async with aiohttp.ClientSession() as session:
            kwargs['headers'] = {
                **get(kwargs, 'headers', {}),
                **self.headers
            }
            return await session.get(f'{self.host}{url}', params=params, **kwargs)


class ClientAPI:

    def __init__(self, host: str, headers: dict = {}):
        self.host = host
        self.headers = headers
        pass

    def open(self, *args, **kwargs):
        _url = args[0] or kwargs['url']
        _url = f'{self.host}{_url}' if 'http' not in _url else _url
        kwargs['headers'] = {
            **get(kwargs, 'headers', {}),
            **self.headers
        }
        response = requests.request(
            **kwargs,
            url=_url
        )
        _response = {}
        try:
            _response = response.json()
        except:
            sentry_sdk.capture_exception()
        return response

    def get(self, *args, **kw):
        """Like open but method is enforced to GET."""
        kw["method"] = "GET"
        return self.open(*args, **kw)

    def patch(self, *args, **kw):
        """Like open but method is enforced to PATCH."""
        kw["method"] = "PATCH"
        return self.open(*args, **kw)

    def post(self, *args, **kw):
        """Like open but method is enforced to POST."""
        kw["method"] = "POST"
        return self.open(*args, **kw)

    def head(self, *args, **kw):
        """Like open but method is enforced to HEAD."""
        kw["method"] = "HEAD"
        return self.open(*args, **kw)

    def put(self, *args, **kw):
        """Like open but method is enforced to PUT."""
        kw["method"] = "PUT"
        return self.open(*args, **kw)

    def delete(self, *args, **kw):
        """Like open but method is enforced to DELETE."""
        kw["method"] = "DELETE"
        return self.open(*args, **kw)

    def options(self, *args, **kw):
        """Like open but method is enforced to OPTIONS."""
        kw["method"] = "OPTIONS"
        return self.open(*args, **kw)

    def trace(self, *args, **kw):
        """Like open but method is enforced to TRACE."""
        kw["method"] = "TRACE"
        return self.open(*args, **kw)
