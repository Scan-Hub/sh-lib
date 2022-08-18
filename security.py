# -*- coding: utf-8 -*-
"""
   Description:
        -
        -
"""
import base64
import json
import traceback
from datetime import timezone
from functools import wraps
import werkzeug
import sentry_sdk
from eth_account.messages import defunct_hash_message
from flask import request, g, current_app
from pydash import get
from marshmallow import Schema
from bson import json_util
from .exception import BadRequest, Forbidden
from .logger import debug
from .utils import util_web3, dt_utcnow


def auth_error_callback(status_code):
    if status_code == 403:
        return {
            "me"
        }


class HTTPSecurity:
    def __init__(self, redis, auth_address: str, *args, **kwargs):
        self.redis = redis
        self.auth_address = auth_address.lower()
        pass

    def get_token(self):
        try:
            auth_type, token = request.headers['Authorization'].split(
                None, 1)

            if auth_type != 'Bearer':
                return False, None

            if not token:
                return False, None
            _token_base64_bytes = token.encode()
            _token_byte = base64.b64decode(_token_base64_bytes)
            _payload = _token_byte.decode()
            return token, json.loads(_payload)
        except (ValueError, KeyError):
            # The Authorization header is either empty or has no token
            pass
        return False, None

    def verify_token(self):
        try:
            _token, _info = self.get_token()
            debug(f'signature {_info}')

            if not _token:
                return False

            if "signature" not in _info:
                return False

            _signature = get(_info, 'signature')
            _payload = get(_info, 'payload')

            _msg_hash = defunct_hash_message(text=_payload)

            _address = util_web3.eth.account.recoverHash(
                _msg_hash,
                signature=_signature
            )

            if self.auth_address != _address.lower():
                debug(f'auth_address {self.auth_address} {_address.lower()}')
                return False
            else:
                payload = json_util.loads(_payload)
                if get(payload, 'exp').replace(tzinfo=timezone.utc) < dt_utcnow():
                    debug(f'exp {_info}')
                    return False
                print(payload)
                user = get(payload, 'payload')
                _user_id = get(user, '_id')
                if not self.redis.exists(f'tokens:{_user_id}:{_token}'):
                    debug(f'exists ex {_info}')
                    return False

                g.current_user = user
                return user
        except:
            sentry_sdk.capture_exception()
            traceback.print_exc()
            return False

    def ensure_sync(self, f):
        try:
            return current_app.ensure_sync(f)
        except AttributeError:  # pragma: no cover
            return f

    def _verify_data(self, f=None, schema=None, response=None):
        def verify_data_internal(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                return self.ensure_sync(f)(*args, **kwargs)

            return decorated

        if f:
            return verify_data_internal(f)
        return verify_data_internal

    def get_user_roles(self, user):
        return get(user, 'roles', default=[])

    def get_headers(self):
        return dict(request.headers)

    def authorize(self, role, user):
        if role is None:
            return True
        if isinstance(role, (list, tuple)):
            roles = role
        else:
            roles = [role]

        user_roles = self.ensure_sync(self.get_user_roles)(user)
        if user_roles is None:
            user_roles = {}
        elif not isinstance(user_roles, (list, tuple)):
            user_roles = {user_roles}
        else:
            user_roles = set(user_roles)
        for role in roles:
            if isinstance(role, (list, tuple)):
                role = set(role)
                if role & user_roles == role:
                    return True
            elif role in user_roles:
                return True

    def http(self, f=None,
             form_data: Schema = None,
             params: Schema = None,
             response: Schema = None,
             login_required: bool = None,
             roles: list = [], *args,
             **kwargs):
        #
        """
        :param params: (marshmallow.Schema) loads data from params
        :param roles:
        :param login_required:
        :param response: (marshmallow.Schema) loads data from controller
        :param form_data: (marshmallow.Schema) dumps data to dict from body or form
        :param f:
        :return:
        """

        def http_internal(f):
            @wraps(f)
            def decorated(*args, **kwargs):

                res = {
                    'data': {},
                    'errors': [],
                    'msg': '',
                    'error_code': ''
                }

                status = 200
                _data = None
                _user = None
                try:

                    # Verify request
                    if login_required:
                        _user = self.verify_token()
                        if not _user:
                            raise Forbidden(errors=[{
                                "user": "Invalid"
                            }])

                        if roles:
                            if not self.authorize(role=roles, user=_user):
                                raise Forbidden(errors=[{
                                    "scope_required": roles
                                }])
                        kwargs['user'] = _user
                    if form_data:

                        if request.content_type.startswith("multipart/form-data"):
                            _data = request.form.to_dict()
                        else:
                            _data = request.json

                        _validate = form_data.validate(_data)
                        if _validate:
                            _errors = _validate if isinstance(_validate, list) else [_validate]
                            raise BadRequest(msg="Invalid data", errors=_errors)
                        _data = form_data.dump(_data)

                        kwargs['form_data'] = _data
                    if params:
                        _params = request.args.to_dict()
                        _validate_query = params.validate(_params)
                        if _validate_query:
                            _errors = _validate_query if isinstance(_validate_query, list) else [_validate_query]
                            raise BadRequest(msg="Invalid params", errors=_errors)
                        _params = params.dump(_params)
                        kwargs['params'] = _params

                    _result = self.ensure_sync(f)(*args, **kwargs)
                    if response:
                        _result = response.load(_result)
                    res['data'] = _result

                except Exception as e:

                    if isinstance(e, werkzeug.wrappers.request.BadRequest):
                        res['msg'] = str(e)
                        status = 400
                        res['error_code'] = 'E_BAD_REQUEST'
                    else:
                        if hasattr(e, 'status_code'):
                            status = e.status_code
                        else:
                            status = 500

                        if hasattr(e, 'msg'):
                            res['msg'] = e.msg
                        else:
                            res['msg'] = "Internal Server Error"

                        if hasattr(e, 'error_code'):
                            res['error_code'] = e.error_code
                        else:
                            res['error_code'] = "E_SERVER"

                        if hasattr(e, 'errors'):
                            res['errors'] = e.errors if isinstance(e.errors, list) else [e.errors]

                        if status == 500:
                            sentry_sdk.capture_exception()
                            traceback.print_exc()

                return res, status

            return decorated

        if f:
            return http_internal(f)
        return http_internal
