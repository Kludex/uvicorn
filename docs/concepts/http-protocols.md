# HTTP Protocols

Uvicorn provides several HTTP protocol implementations that you can choose from using the [`--http`](../settings.md#implementation) option:

```bash
uvicorn main:app --http <auto|h11|httptools|zttp|zttp1|zttp2>
```

By default, Uvicorn uses `--http auto`, which automatically selects:

1. **httptools** - If [httptools](https://github.com/MagicStack/httptools) is installed, Uvicorn will use it for maximum performance
2. **h11** - If httptools is not available, Uvicorn falls back to [h11](https://github.com/python-hyper/h11)

## h11

[h11](https://github.com/python-hyper/h11) is a pure Python HTTP/1.1 implementation. It is a required dependency of Uvicorn, so it is always available, and it is the only implementation compatible with PyPy.

## httptools

[httptools](https://github.com/MagicStack/httptools) is a Python binding for the Node.js HTTP parser. It is installed as part of the `uvicorn[standard]` optional extras, and provides greater performance than h11, but is not compatible with PyPy.

## zttp

[zttp](https://zttp.marcelotryle.com/) is a sans-IO HTTP parser for Python with a core written in Zig. Prebuilt wheels are available for CPython on Linux, macOS and Windows.

You can install it with:

=== "pip"
    ```bash
    pip install zttp
    ```
=== "uv"
    ```bash
    uv add zttp
    ```

You can run `uvicorn` with `zttp` with the following command:

```bash
uvicorn main:app --http zttp
```

zttp is the only implementation with HTTP/2 support. It comes in three variants: `zttp`
serves both HTTP/1.1 and HTTP/2, `zttp1` serves HTTP/1.1 only, and `zttp2` serves HTTP/2
only. See the [HTTP/2 documentation](http2.md) for details.

!!! warning "Experimental"
    zttp support is currently **experimental** and **not suited for production usage**. If you try it out, please report any issues or feedback on the [issue tracker](https://github.com/Kludex/uvicorn/issues).
