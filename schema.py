# -*- coding: utf-8 -*-
"""
   Description:
        -
        -
"""
from __future__ import annotations

import typing

from marshmallow import ValidationError
from marshmallow.validate import Validator

from .utils import is_oid

from datetime import datetime, timezone

from bson import ObjectId
from marshmallow import fields


class ObjectIdField(fields.Field):
    def _serialize(self, value, attr, obj, **kwargs):
        if value and isinstance(value, str):
            return ObjectId(value)
        return value

    def _deserialize(
            self,
            value,
            *args,
            **kwargs
    ):
        if isinstance(value, ObjectId):
            return str(value)
        return value


class DatetimeField(fields.Field):
    def _serialize(self, value, attr, obj, **kwargs):
        MIN_YEAR = 1
        MAX_YEAR = 9999
        if isinstance(value, (float, int)):
            if MIN_YEAR * 365 * 86400 <= float(value) <= MAX_YEAR * 365 * 86400:
                return datetime.fromtimestamp(value, tz=timezone.utc)
        return value

    def _deserialize(
            self,
            value,
            *args,
            **kwargs
    ):
        if isinstance(value, datetime):
            return value.replace(tzinfo=timezone.utc).timestamp()
        return value


class IsObjectId(Validator):
    message_error = "It must be a 12-byte input or a 24-character hex string."

    def __init__(self):
        pass

    def _repr_args(self) -> str:
        return f""

    def _format_error(self, value: typing.Sized, message: str) -> str:
        return (self.error or message).format(
            value=value
        )

    def __call__(self, value):
        if not is_oid(value):
            raise ValidationError(self._format_error(value, self.message_error))

        return value


class NotBlank(Validator):
    message_error = "Field cannot be blank."

    def __init__(self):
        pass

    def _repr_args(self) -> str:
        return f""

    def _format_error(self, value: typing.Sized, message: str) -> str:
        return (self.error or message).format(
            value=value
        )

    def __call__(self, value):
        value = " ".join(value.split())
        if not value:
            raise ValidationError(self._format_error(value, self.message_error))

        return value
