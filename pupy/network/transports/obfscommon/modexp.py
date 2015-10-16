try:
    from gmpy2 import mpz as mpz
except ImportError:
    try:
        from gmpy import mpz as mpz
    except ImportError:
        def mpz( x ):
            return x
        pass

def powMod( x, y, mod ):
    """
    (Efficiently) Calculate and return `x' to the power of `y' mod `mod'.

    If possible, the three numbers are converted to GMPY's bignum
    representation which speeds up exponentiation.  If GMPY is not installed,
    built-in exponentiation is used.
    """

    x = mpz(x)
    y = mpz(y)
    mod = mpz(mod)
    return pow(x, y, mod)
