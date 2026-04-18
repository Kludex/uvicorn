Uvicorn uses Python's built-in [`logging`](https://docs.python.org/3/library/logging.html)
module, and provides three loggers out of the box:

| Logger name      | Purpose                                            |
|------------------|----------------------------------------------------|
| `uvicorn`        | Parent logger (rarely used directly)               |
| `uvicorn.error`  | Server-level messages (startup, shutdown, errors)   |
| `uvicorn.access` | Per-request access log lines                        |

!!! note
    Despite its name, `uvicorn.error` is **not** limited to error messages.
    It is the general-purpose server logger, similar to how Gunicorn names its
    main logger. See [#562](https://github.com/encode/uvicorn/issues/562) for
    background.

## Default Configuration

By default, Uvicorn applies the following
[`dictConfig()`](https://docs.python.org/3/library/logging.config.html#logging.config.dictConfig)
configuration:

```python
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(levelprefix)s %(message)s",
            "use_colors": None,
        },
        "access": {
            "()": "uvicorn.logging.AccessFormatter",
            "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
        },
    },
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
        },
        "access": {
            "formatter": "access",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
        },
    },
    "loggers": {
        "uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
        "uvicorn.error": {"level": "INFO"},
        "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
    },
}
```

## Custom Logging Configuration

You can supply a custom logging configuration file with the `--log-config`
option (or `log_config` when calling `uvicorn.run()`).

Uvicorn supports three file formats:

| Extension      | Loader                       | Notes                                       |
|----------------|------------------------------|---------------------------------------------|
| `.json`        | `logging.config.dictConfig`  | Standard JSON `dictConfig` schema.          |
| `.yaml`/`.yml` | `logging.config.dictConfig`  | Requires **PyYAML** (`uvicorn[standard]`).  |
| Any other      | `logging.config.fileConfig`  | Classic INI-style format.                   |

### YAML Example

Create a file named `log_config.yaml`:

```yaml
version: 1
disable_existing_loggers: false
formatters:
  default:
    "()": uvicorn.logging.DefaultFormatter
    fmt: "%(asctime)s - %(levelprefix)s %(message)s"
    datefmt: "%Y-%m-%d %H:%M:%S"
    use_colors: null
  access:
    "()": uvicorn.logging.AccessFormatter
    fmt: '%(asctime)s - %(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s'
    datefmt: "%Y-%m-%d %H:%M:%S"
handlers:
  default:
    formatter: default
    class: logging.StreamHandler
    stream: ext://sys.stderr
  access:
    formatter: access
    class: logging.StreamHandler
    stream: ext://sys.stdout
loggers:
  uvicorn:
    handlers:
      - default
    level: INFO
    propagate: false
  uvicorn.error:
    level: INFO
  uvicorn.access:
    handlers:
      - access
    level: INFO
    propagate: false
```

Then pass it to Uvicorn:

=== "CLI"

    ```bash
    uvicorn main:app --log-config log_config.yaml
    ```

=== "Programmatic"

    ```python
    uvicorn.run("main:app", log_config="log_config.yaml")
    ```

### JSON Example

Create a file named `log_config.json`:

```json
{
  "version": 1,
  "disable_existing_loggers": false,
  "formatters": {
    "default": {
      "()": "uvicorn.logging.DefaultFormatter",
      "fmt": "%(asctime)s - %(levelprefix)s %(message)s",
      "datefmt": "%Y-%m-%d %H:%M:%S",
      "use_colors": null
    },
    "access": {
      "()": "uvicorn.logging.AccessFormatter",
      "fmt": "%(asctime)s - %(levelprefix)s %(client_addr)s - \"%(request_line)s\" %(status_code)s",
      "datefmt": "%Y-%m-%d %H:%M:%S"
    }
  },
  "handlers": {
    "default": {
      "formatter": "default",
      "class": "logging.StreamHandler",
      "stream": "ext://sys.stderr"
    },
    "access": {
      "formatter": "access",
      "class": "logging.StreamHandler",
      "stream": "ext://sys.stdout"
    }
  },
  "loggers": {
    "uvicorn": {
      "handlers": ["default"],
      "level": "INFO",
      "propagate": false
    },
    "uvicorn.error": {
      "level": "INFO"
    },
    "uvicorn.access": {
      "handlers": ["access"],
      "level": "INFO",
      "propagate": false
    }
  }
}
```

### Programmatic `dictConfig`

You can also pass a dictionary directly when running programmatically:

```python
import uvicorn

log_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(asctime)s - %(levelprefix)s %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "access": {
            "()": "uvicorn.logging.AccessFormatter",
            "fmt": '%(asctime)s - %(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
        },
        "access": {
            "formatter": "access",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
        },
    },
    "loggers": {
        "uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
        "uvicorn.error": {"level": "INFO"},
        "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
    },
}

uvicorn.run("main:app", log_config=log_config)
```

## Common Recipes

### Writing Logs to a File

To write Uvicorn's server logs to a file in addition to the console, add a `FileHandler` to the `uvicorn` logger:

```yaml
version: 1
disable_existing_loggers: false
formatters:
  default:
    "()": uvicorn.logging.DefaultFormatter
    fmt: "%(asctime)s - %(levelprefix)s %(message)s"
    datefmt: "%Y-%m-%d %H:%M:%S"
    use_colors: false
  access:
    "()": uvicorn.logging.AccessFormatter
    fmt: '%(asctime)s - %(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s'
    datefmt: "%Y-%m-%d %H:%M:%S"
handlers:
  default:
    formatter: default
    class: logging.StreamHandler
    stream: ext://sys.stderr
  access:
    formatter: access
    class: logging.StreamHandler
    stream: ext://sys.stdout
  file:
    formatter: default
    class: logging.FileHandler
    filename: uvicorn.log
loggers:
  uvicorn:
    handlers:
      - default
      - file
    level: INFO
    propagate: false
  uvicorn.error:
    level: INFO
  uvicorn.access:
    handlers:
      - access
    level: INFO
    propagate: false
```

In this example, `uvicorn.access` still writes to stdout only. To write access
logs to the file as well, add `file` to the `uvicorn.access.handlers` list.

### Disabling Access Logs

Use the `--no-access-log` CLI flag, or set `access_log=False` programmatically.
This removes all handlers from `uvicorn.access` without affecting the
`uvicorn.error` logger.

### Disabling Colors

Pass `--no-use-colors` on the command line, or set `use_colors=False`
programmatically. When using a custom `--log-config`, set `use_colors: false`
on each formatter that extends `uvicorn.logging.ColourizedFormatter`.

### Using a Standard Formatter

If you do not need Uvicorn's colorized output, you can use the standard
`logging.Formatter` instead:

```yaml
version: 1
disable_existing_loggers: false
formatters:
  default:
    format: "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    datefmt: "%Y-%m-%d %H:%M:%S"
handlers:
  default:
    formatter: default
    class: logging.StreamHandler
    stream: ext://sys.stderr
loggers:
  uvicorn:
    handlers:
      - default
    level: INFO
    propagate: false
  uvicorn.error:
    level: INFO
  uvicorn.access:
    handlers:
      - default
    level: INFO
    propagate: false
```

!!! warning
    When using a standard `logging.Formatter` for the access logger, the
    `%(client_addr)s`, `%(request_line)s`, and `%(status_code)s` placeholders
    are **not** available. The access log line will be formatted using only the
    standard `%(message)s` field.
