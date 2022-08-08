# -*- coding: utf-8 -*-
"""
   Description:
        -
        -
"""
import logging
import sys
import traceback
from inspect import getframeinfo, stack

DEBUG_LEVEL = logging.DEBUG

logger = logging.getLogger('logger')
logger.setLevel(DEBUG_LEVEL)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(DEBUG_LEVEL)
formatter = logging.Formatter('%(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

from bson import json_util


def debug(msg, *args, **kwargs):
    try:
        caller = getframeinfo(stack()[1][0])
        _msg = json_util.dumps({
            'msg': msg,
            'args': args,
            'kwargs': kwargs,
            'filename': caller.filename,
            'lineno': caller.lineno
        })
        logger.debug(_msg)
    except:
        traceback.print_exc()
