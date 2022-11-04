__all__ = ["getline", "clearcache", "checkcache", "lazycache"]

def getline(filename, lineno, module_globals=None):
    return ''


def clearcache():
    pass


def getlines(filename, module_globals=None):
    return []

def getline(filename, lineno, module_globals=None):
    return ''


def checkcache(filename=None):
    pass


def updatecache(filename, module_globals=None):
    pass

def lazycache(filename, module_globals):
    return False
