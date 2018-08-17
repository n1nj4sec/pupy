# -*- coding: utf-8 -*-

def to_string(x):
    if type(x) in (list, tuple, set, frozenset):
        return [to_string(y) for y in x]
    elif type(x) in (str, unicode):
        return x
    elif x is None:
        return ''
    elif type(x) == dict:
        return {
            to_string(k):to_string(v) for k,v in x.iteritems()
        }
    else:
        return unicode(x)

def to_strings_list(function, *args, **kwargs):
    results = []
    raise_on_exception = kwargs.pop('raise_on_exception', True)

    iterator = function(*args, **kwargs)

    while True:
        try:
            result = iterator.next()
            results.append(to_string(result))

        except StopIteration:
            break

        except:
            if raise_on_exception:
                raise

    return results
