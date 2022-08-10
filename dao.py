# -*- coding: utf-8 -*-
"""
   Description:
        -
        -
"""
from bson import ObjectId, json_util
from celery import Celery
from pydash import get

from .utils import dt_utcnow, is_oid


def to_str(x):
    if isinstance(x, ObjectId):
        return str(x)
    if not isinstance(x, str):
        return json_util.dumps(x)
    return x


class Cache:
    def __init__(self, col, redis):
        """
        hset, hget for list (required: hset_field)
        set, get for one
        Run script: python3 sync/collection.py db=<db name> col=<collection name> key_sync=<list keys form filter> hset_field=<field_key> tll=-1
        Note:
            - key_sync=user_id - with data-based user id
            - key_sync=on_market#true - with on_market=true is required, it doesn't change
        EX:
            Run:  python3 sync/collection.py db=core col=users key_sync=on_market#true type=_id  tll=-1

            Model.find(filter={"on_market": True}, hset_field='_id')

        :param col:
        """
        # The full name is of the form `database_name.collection_name`.
        self.full_name = col.full_name
        self.redis = redis

    def _key(self, filter):
        _filter_keys = list(filter.keys())

        _filter_keys.sort()

        _fields = [f'{x}:{to_str(filter[x])}' for x in _filter_keys]

        return f'{self.full_name}:{":".join(_fields)}'

    def _hget(self, key):
        _raws = self.redis.hvals(key)
        if _raws is not None:
            return [json_util.loads(_raw) for _raw in _raws if _raw]
        return None

    def _hset(self, key, raws, hset_field):

        if not raws:
            self.redis.hset(key, '', '')

        for _raw in raws:
            self.redis.hset(key, to_str(get(_raw, hset_field)), json_util.dumps(_raw))

    def _get(self, key):
        _raw = self.redis.get(key)
        if _raw is not None:
            return json_util.loads(_raw) if _raw else {}
        return None

    def _set(self, key, raw):
        if not raw:
            raw = {}
        raw = json_util.dumps(raw)
        self.redis.set(key, raw)

    def find_one_with_cache(self, filter, query):
        _key = self._key(filter)
        _item = self._get(_key)
        if _item is None:
            _item = query()
            self._set(key=_key, raw=_item)

        return _item

    def find_with_cache(self, filter, hset_field, query):
        _key = self._key(filter)
        _items = self._hget(_key)
        if _items is None:
            _items = query()
            self._hset(key=_key, raws=_items, hset_field=hset_field)

        return _items

    def user(self, user_id):
        """
            Get info of a user
        :param user_id:
        :return:
        """
        if not is_oid(user_id):
            return {}
        _user = self.redis.get(f'global.users:_id:{user_id}')
        if not _user:
            return {}
        return json_util.loads(_user)


class InterfaceTask:
    def __init__(self, name, queue_name, broker):
        self.name = name
        self.queue_name = queue_name
        self.queue = Celery(
            queue=queue_name,
            broker=broker
        )

    def delay(self, *args, **kwargs):
        self.queue.send_task(
            args=args,
            kwargs=kwargs,
            name=self.name,
            queue=self.queue_name
        )


class DaoModel(Cache):
    def __init__(self, col, redis=None, broker=None):
        super(DaoModel, self).__init__(col, redis)
        self.col = col
        print({
            'name': f"worker.model.{self.col.name}",
            'queue': f"{self.col.database.name}-queue"
        })
        self.task_name = f"worker.model.{self.col.name}"
        self.queue = InterfaceTask(
            name=self.task_name,
            queue_name=f"{self.col.database.name}-queue",
            broker=broker
        ) if broker else None

    def insert_one(self, row: dict, worker=False):
        row['created_time'] = dt_utcnow()
        row['updated_time'] = dt_utcnow()
        if 'created_by' not in row:
            raise Exception('Required created_by')
        if worker:
            row['_id'] = ObjectId()
            self.worker(
                func='insert_one',
                row=row
            )
            return row
        else:
            return self.col.insert_one(row)

    def update_one(self, filter: dict, obj: dict, *args, **kwargs):

        obj['updated_time'] = dt_utcnow()

        if 'updated_by' not in obj:
            raise Exception('Required updated_by')
        if get(kwargs, 'worker'):
            self.worker(
                func='update_one',
                filter=filter,
                obj=obj,
                *args, **kwargs
            )
        else:
            return self.col.update_one(filter=filter, update={
                '$set': obj
            }, *args, **kwargs)

    def worker(self, func, *args, **kwargs):
        self.queue.delay(msg={
            'func': func,
            'model': self.__class__.__name__,
            'payload': json_util.dumps({
                'args': args,
                'kwargs': kwargs
            })
        })

    def update_many(self, filter: dict, obj: dict, *args, **kwargs):

        obj['updated_time'] = dt_utcnow()

        if 'updated_by' not in obj:
            raise Exception('Required updated_by')
        if get(kwargs, 'worker'):
            self.worker(
                func='update_many',
                filter=filter,
                obj=obj,
                *args, **kwargs
            )
        else:
            return self.col.update_many(filter=filter, update={
                '$set': obj
            }, *args, **kwargs)

    def insert_many(self, rows, worker=False):
        for row in rows:
            row['created_time'] = dt_utcnow()

            if 'created_time' not in row:
                raise Exception('Required created_time')
        if worker:
            self.worker(
                func='insert_many',
                rows=rows
            )
        else:
            return self.col.insert_many(rows)

    def find_one(self, filter: dict, *args, **kwargs):
        def _query():
            return self.col.find_one(filter=filter, *args, **kwargs)

        if get(kwargs, 'cache'):
            return self.find_one_with_cache(filter=filter, query=_query)
        return _query()

    def find(self, filter: dict, *args, **kwargs):
        """

        :param filter:
        :param args:
        :param kwargs:
            - hset_field: field of hset in cache
        :return:
        """

        def _query():
            return self.col.find(filter=filter, *args, **kwargs)

        if get(kwargs, 'cache'):
            return self.find_with_cache(filter=filter, hset_field=get(kwargs, 'hset_field', '_id'), query=_query)
        return _query()

    def page(self, filter, page_size: int, page: int, sort=1, func_sort=None, func_filter=None, hset_field='_id'):
        _list = self.find(filter=filter, hset_field=hset_field)
        if func_filter:
            _list = [x for x in _list if func_filter(x)]
        if func_sort:
            if sort == 1:
                _list.sort(key=func_sort)
            else:
                _list.sort(key=func_sort, reverse=True)
        _offset = page_size * (page - 1)
        _limit = (int(page * page_size))
        _offset = int(_limit - page_size)
        result = _list[_offset:_limit]
        num_of_page = (len(_list) / page_size)
        if (len(_list) % page_size) > 0:
            num_of_page = num_of_page + 1

        return {
            "items": result,
            'num_of_page': num_of_page,
            'page_size': page_size,
            'page': page
        }


class AsyncDaoModel:
    def __init__(self, col):
        self.col = col

    async def insert_one(self, row: dict):
        row['created_time'] = dt_utcnow()
        row['updated_time'] = dt_utcnow()
        if 'created_by' not in row:
            raise Exception('Required created_by')
        return await self.col.insert_one(row)

    async def update_one(self, filter: dict, obj: dict, *args, **kwargs):

        obj['updated_time'] = dt_utcnow()

        if 'updated_by' not in obj:
            raise Exception('Required updated_by')

        return await self.col.update(filter=filter, update={
            '$set': obj
        }, *args, **kwargs)

    async def update_many(self, filter: dict, obj: dict, *args, **kwargs):

        obj['updated_time'] = dt_utcnow()

        if 'updated_by' not in obj:
            raise Exception('Required updated_by')

        return await self.col.update_many(filter=filter, update={
            '$set': obj
        }, *args, **kwargs)

    async def insert_many(self, rows):
        for row in rows:
            row['created_time'] = dt_utcnow()

            if 'created_time' not in row:
                raise Exception('Required created_time')

        return await self.col.insert_many(rows)

    async def find_one(self, filter):
        doc = await self.col.find_one(filter)
        return doc
