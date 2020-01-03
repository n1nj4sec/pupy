import sys
from bundlevars import bundlevars

def parse_config_h(fp, vars=None):
    return {}


def get_config_h_filename():
    return None


def get_scheme_names():
    return tuple()


def get_path_names():
    return tuple()


def get_paths(scheme=None, vars=None, expand=True):
    return tuple()


def get_path(name, scheme=None, vars=None, expand=True):
    return ''


def get_config_vars(*args):
    if not args:
        return dict(bundlevars)

    return {
        k: bundlevars.get(k, None) for k in args
    }


def get_config_var(name):
    return None


def get_platform():
    return sys.platform


def get_python_version():
    return '.'.join(sys.version.split('.', 3)[:2])
