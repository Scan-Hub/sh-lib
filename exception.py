# -*- coding: utf-8 -*-
"""
   Description:
        -
        -
"""


class BadRequest(Exception):
    def __init__(self, msg='Something wrong.', *args: object, **kwargs) -> None:
        super().__init__(*args)
        self.status_code = 400
        self.msg = msg
        self.errors = kwargs.get('errors', [])
        self.error_code = 'E_BAD_REQUEST'

    pass


class Forbidden(Exception):
    def __init__(self, *args: object, **kwargs) -> None:
        super().__init__(*args)
        self.status_code = 403
        self.msg = 'Forbidden'
        self.errors = kwargs.get('errors', [])
        self.error_code = 'E_FORBIDDEN'

    pass


class NotFound(Exception):
    def __init__(self, msg='not found', *args: object, **kwargs) -> None:
        super().__init__(*args)
        self.status_code = 404
        self.msg = msg
        self.errors = kwargs.get('errors', [])
        self.error_code = 'E_NOT_FOUND'

    pass

