# Copyright (c) 2010, 2011, 2012, 2015 Guilherme Gondim. All rights reserved.
# Copyright (c) 2009 Simon Willison. All rights reserved.
# Copyright (c) 2002 Drew Perttula. All rights reserved.
#
# License:
#   Python Software Foundation License version 2
#
# See the file "LICENSE" for terms & conditions for usage, and a DISCLAIMER OF
# ALL WARRANTIES.
#
# This Baseconv distribution contains no GNU General Public Licensed (GPLed)
# code so it may be used in proprietary projects just like prior ``baseconv``
# distributions.
#
# All trademarks referenced herein are property of their respective holders.
#

"""
Convert numbers from base 10 integers to base X strings and back again.

Sample usage::

  >>> base20 = BaseConverter('0123456789abcdefghij')
  >>> base20.encode(1234)
  '31e'
  >>> base20.decode('31e')
  '1234'
  >>> base20.encode(-1234)
  '-31e'
  >>> base20.decode('-31e')
  '-1234'
  >>> base11 = BaseConverter('0123456789-', sign='$')
  >>> base11.encode('$1234')
  '$-22'
  >>> base11.decode('$-22')
  '$1234'

"""


BASE2_ALPHABET = '01'
BASE16_ALPHABET = '0123456789ABCDEF'
BASE36_ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyz'
BASE56_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz'
BASE62_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
BASE64_ALPHABET = BASE62_ALPHABET + '-_'


class BaseConverter(object):
    decimal_digits = '0123456789'

    def __init__(self, digits, sign='-'):
        self.sign = sign
        self.digits = digits
        if sign in self.digits:
            raise ValueError('Sign character found in converter base digits.')

    def __repr__(self):
        return "BaseConverter(%r, sign=%r)" % (self.digits, self.sign)

    def _convert(self, number, from_digits, to_digits):
        if str(number)[0] == self.sign:
            number = str(number)[1:]
            neg = True
        else:
            neg = False

        # make an integer out of the number
        x = 0
        for digit in str(number):
            x = x * len(from_digits) + from_digits.index(digit)

        # create the result in base 'len(to_digits)'
        if x == 0:
            res = to_digits[0]
        else:
            res = ''
            while x > 0:
                digit = x % len(to_digits)
                res = to_digits[digit] + res
                x = int(x // len(to_digits))
        return neg, res

    def encode(self, number):
        neg, value = self._convert(number, self.decimal_digits, self.digits)
        if neg:
            return self.sign + value
        return value

    def decode(self, number):
        neg, value = self._convert(number, self.digits, self.decimal_digits)
        if neg:
            return self.sign + value
        return value


base2 = BaseConverter(BASE2_ALPHABET)
base16 = BaseConverter(BASE16_ALPHABET)
base36 = BaseConverter(BASE36_ALPHABET)
base56 = BaseConverter(BASE56_ALPHABET)
base62 = BaseConverter(BASE62_ALPHABET)
base64 = BaseConverter(BASE64_ALPHABET, sign='$')


if __name__ == '__main__':
    # doctests
    import doctest
    doctest.testmod()

    # other tests
    nums = [-10 ** 10, 10 ** 10] + list(range(-100, 100))
    for converter in [base2, base16, base36, base56, base62, base64]:
        if converter.sign == '-':
            for i in nums:
                assert i == int(converter.decode(converter.encode(i))), '%s failed' % i
        else:
            for i in nums:
                i = str(i)
                if i[0] == '-':
                    i = converter.sign + i[1:]
                assert i == converter.decode(converter.encode(i)), '%s failed' % i
