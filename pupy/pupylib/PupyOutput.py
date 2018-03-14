# -*- encoding: utf-8 -*-

class Hint(object):
    __slots__ = ()

class Text(Hint):
    __slots__ = ( 'data' )

    def __init__(self, data):
        self.data = data

    def __repr__(self):
        return '<Hint({}): {}>'.format(
            self.__class__.__name__,
            repr(self.data))

    def __str__(self):
        raise NotImplementedError(
            '__str__ is not implemented for class {}'.format(
                self.__class__.__name__))

class Table(Text):
    __slots__ = ( 'headers', 'caption', 'legend' )
    def __init__(self, data, headers=None, caption=None, legend=True):
        super(Table, self).__init__(data)
        self.headers = headers
        self.caption = caption
        self.legend = legend

class Stream(Text):
    __slots__ = ()

class Line(Text):
    __slots__ = ()

    def __init__(self, *args):
        super(Line, self).__init__(args)

class TruncateToTerm(Text):
    __slots__ = ()

class Color(Text):
    __slots__ = ('color')

    def __init__(self, data, color):
        super(Color, self).__init__(data)
        self.color = color

class Title(Text):
    __slots__ = ()

class MultiPart(Text):
    __slots__ = ()

class NewLine(Text):
    __slots__ = ()

    def __init__(self, lines=1):
        super(NewLine, self).__init__(lines)

class Log(Text):
    __slots__ = ()

class Info(Text):
    __slots__ = ()

class ServiceInfo(Text):
    __slots__ = ()

class Warn(Text):
    __slots__ = ()

class Error(Text):
    __slots__ = ( 'header' )

    def __init__(self, error, header=None):
        super(Error, self).__init__(error)
        self.header = header

class Success(Text):
    __slots__ = ()

class Section(Text):
    __slots__ = ( 'header' )

    def __init__(self, header, data):
        super(Section, self).__init__(data)
        self.header = header

class Usage(Text):
    __slots__ = ( 'module' )

    def __init__(self, module, data):
        super(Usage, self).__init__(data)
        self.module = module

class Interact(Hint):
    __slots__ = ()

class Prompt(Interact):
    __slots__ = ( 'request', 'hide' )

    def __init__(self, request, hide=False):
        self.request = request
        self.hide = hide

class Terminal(Hint):
    __slots__ = ()
