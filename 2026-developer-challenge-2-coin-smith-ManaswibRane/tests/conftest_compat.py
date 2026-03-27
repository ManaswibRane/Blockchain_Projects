import sys

class _RaisesCtx:
    def __init__(self, exc_type):
        self.exc_type = exc_type
        self.value = None
    def __enter__(self): return self
    def __exit__(self, exc_type, exc_val, tb):
        if exc_type is None:
            raise AssertionError(f"Expected {self.exc_type.__name__} to be raised")
        if not issubclass(exc_type, self.exc_type):
            return False
        self.value = exc_val
        return True

class _PytestShim:
    @staticmethod
    def raises(exc_type): return _RaisesCtx(exc_type)

if 'pytest' not in sys.modules:
    sys.modules['pytest'] = _PytestShim()