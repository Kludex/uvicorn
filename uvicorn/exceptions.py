from __future__ import annotations


class UvicornDeprecationWarning(UserWarning):
    """A custom deprecation warning for Uvicorn.

    Unlike the built-in DeprecationWarning, this inherits from UserWarning to ensure it is visible by default, helping
    users discover deprecated features without needing to enable warnings explicitly.

    Reference: https://sethmlarson.dev/deprecations-via-warnings-dont-work-for-python-libraries
    """
