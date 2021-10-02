import sys
from calendar import timegm
from datetime import datetime
from datetime import timedelta
from importlib import import_module
from typing import Union


def str2timedelta(s: Union[str, timedelta]) -> timedelta:
    if not isinstance(s, str):
        return s
    t = datetime.strptime(s, '%H:%M:%S')
    return timedelta(hours=t.hour, minutes=t.minute, seconds=t.second)


def str2bytes(s: Union[str, bytes]) -> bytes:
    if isinstance(s, bytes):
        return s
    return str.encode(s)


def datetime_to_epoch(dt):
    return timegm(dt.utctimetuple())


def datetime_from_epoch(ts):
    return datetime.utcfromtimestamp(ts)


def cached_import(module_path, class_name):
    # source: https://git.io/JzX1K
    modules = sys.modules
    if module_path not in modules or (
        getattr(modules[module_path], '__spec__', None) is not None
        and getattr(modules[module_path].__spec__, '_initializing', False)
        is True
    ):
        import_module(module_path)
    return getattr(modules[module_path], class_name)


def import_string(dotted_path):
    # source: https://git.io/JzX15
    try:
        module_path, class_name = dotted_path.rsplit('.', 1)
    except ValueError as err:
        raise ImportError(
            "%s doesn't look like a module path" % dotted_path,
        ) from err

    try:
        return cached_import(module_path, class_name)
    except AttributeError as err:
        raise ImportError(
            'Module "%s" does not define a "%s" attribute/class'
            % (module_path, class_name),
        ) from err
