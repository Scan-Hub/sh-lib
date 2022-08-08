# -*- coding: utf-8 -*-
"""
   Description:
        -
        -
"""
from datetime import datetime, timezone

from bson import ObjectId
from web3 import Web3

util_web3 = Web3()


def dt_utcnow():
    return datetime.utcnow().replace(tzinfo=timezone.utc)


def is_oid(oid: str) -> bool:
    return ObjectId.is_valid(oid)


def get_default(default):
    if callable(default):
        return default()
    return default
