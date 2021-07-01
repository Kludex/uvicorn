# Change Log

## 0.15.0 - 2021-07-<???>

### Added
* Adapt bind_socket to make it usable with multiple processes (#1009) 21/06/21
* Add existence check to the reload directory(ies) (#1089) 21/06/21
* Add missing trace log for websocket protocols (#1083) 19/06/21
* Add option to set websocket ping interval and timeout (#1048) 09/06/21
* Docs: Add uvloop and httptools related info (#1071) 09/06/21
* Support disabling default Server and Date headers (#818) 11/06/21

### Changed
* Add PEP440 compliant version of click (#1099) 29/06/21
* Bump asgiref to 3.4.0 (#1100) 29/06/21

### Fixed
* Exit with status 3 when worker starts failed (#1077) 22/06/21
* Revert propagate status after exiting context caplog_for_logger() (#1086) 19/06/21

## 0.14.0 - 2021-06-01

### Added

* Defaults ws max_size on server to 16MB (#995) 5/29/21
* Improve user feedback if no ws library installed (#926 and #1023) 2/27/21
* Support 'reason' field in 'websocket.close' messages (#957) 2/24/21
* Implemented lifespan.shutdown.failed (#755) 2/25/21

### Changed

* Upgraded websockets requirements (#1065)  6/1/21
* Switch to asyncio streams API (#869) 5/29/21
* Update httptools from 0.1.* to 0.2.* (#1024) 5/28/21
* Allow Click 8.0, refs #1016 (#1042) 5/23/21
* Add search for a trusted host in ProxyHeadersMiddleware (#591) 3/13/21
* Up wsproto to 1.0.0 (#892) 2/25/21

### Fixed

* Force reload_dirs to be a list (#978) 6/1/21
* Fix gunicorn worker not running if extras not installed (#901) 5/28/21
* Fix socket port 0 (#975) 3/5/21
* Prevent garbage collection of main lifespan task (#972) 3/4/21

## 0.13.4 - 2021-02-20

### Fixed

* Fixed wsgi middleware PATH_INFO encoding (#962) 2/20/21
* Fixed uvloop dependency  (#952) 2/10/21 then (#959) 2/20/21
* Relax watchgod up bound (#946) 1/31/21
* Return 'connection: close' header in response (#721) 1/25/21

### Added:

* Docs: Nginx + websockets (#948) 2/10/21
* Document the default value of 1 for workers (#940) (#943) 1/25/21
* Enabled permessage-deflate extension in websockets (#764) 1/1/21

## 0.13.3 - 2020-12-29

### Fixed

* Prevent swallowing of return codes from `subprocess` when running with Gunicorn by properly resetting signals. (Pull #895)
* Tweak detection of app factories to be more robust. A warning is now logged when passing a factory without the `--factory` flag. (Pull #914)
* Properly clean tasks when handshake is aborted when running with `--ws websockets`. (Pull #921)

## 0.13.2 - 2020-12-12

### Fixed

* Log full exception traceback in case of invalid HTTP request. (Pull #886 and #888)

## 0.13.1 - 2020-12-12

### Fixed

* Prevent exceptions when the ASGI application rejects a connection during the WebSocket handshake, when running on both `--ws wsproto` or `--ws websockets`. (Pull #704 and #881)
* Ensure connection `scope` doesn't leak in logs when using JSON log formatters. (Pull #859 and #884)

## 0.13.0 - 2020-12-08

### Added

* Add `--factory` flag to support factory-style application imports. (#875) 2020-12-07 50fc0d1c
* Skip installation of signal handlers when not in the main thread. Allows using `Server` in multithreaded contexts without having to override `.install_signal_handlers()`. (#871) 2020-12-07 ce2ef45a

## 0.12.3 - 2020-11-21

### Fixed

* Fix race condition that leads Quart to hang with uvicorn (#848) 11/18/20 de213614
* Use latin1 when decoding X-Forwarded-* headers (#701) 11/12/20 45e6e831
* Rework IPv6 support (#837) 11/8/20 bdab488e
* Cancel old keepalive-trigger before setting new one. (#832) 10/26/20 d5dcf80c

## 0.12.2 - 2020-10-19

### Added

* Adding ability to decrypt ssl key file (#808) 10/12/20 90dbb6e0
* Support .yml log config files (#799) 10/6/20 b468950e
* Added python 3.9 support (#804) 10/6/20 08fd0559

### Fixed

* Fixes watchgod with common prefixes (#817) 10/14/20 1b32f997
* Fix reload with ipv6 host (#803) 10/14/20 5acaee5b
* Added cli suport for headers containing colon (#813) 10/12/20 68732899
* Sharing socket across workers on windows (#802) 10/12/20 103167a0
* Note the need to configure trusted "ips" when using unix sockets (#796) 10/4/20 a504c569

## 0.12.1 - 2020-09-30

### Changed

* Pinning h11 and python-dotenv to min versions (#789) 9/29/20 bbf19c66
* Get docs/index.md in sync with README.md (#784) 9/29/20 70ebcfdf

### Fixed

* Improve changelog by pointing out breaking changes (#792) 9/29/20 e2b75064

## 0.12.0 - 2020-09-28

### Added

* Make reload delay configurable (#774) 9/28/20 98010027
* Upgrade maximum h11 dependency version to 0.10 (#772) 8/28/20 54d729cc
* Allow .json or .yaml --log-config files (#665) 8/18/20 093a1f7c
* Add ASGI dict to the lifespan scope (#754) 8/15/20 8150c3eb
* Upgrade wsproto to 0.15.0 (#750) 8/13/20 fbce393f
* Use optional package installs (#666) 8/10/20 5fa99a11

### Changed

* Dont set log level for root logger (#767) 8/28/20 df81b168
* Uvicorn no longer ships extra dependencies `uvloop`,  `websockets` and
`httptools` as default. To install these dependencies use
`uvicorn[standard]` .

### Fixed

* Revert "Improve shutdown robustness when using `--reload` or multiprocessing (#620)" (#756) 8/28/20 ff4af12d
* Fix terminate error in windows (#744) 8/27/20 dd3b842d
* Fix bug where --log-config disables uvicorn loggers (#512) 8/11/20 a9c37cc4

## 0.11.8 - 2020-07-30

* Fix a regression that caused Uvicorn to crash when using `--interface=wsgi`. (Pull #730)
* Fix a regression that caused Uvicorn to crash when using unix domain sockets. (Pull #729)

## 0.11.7 - 2020-28-07

* SECURITY FIX: Prevent sending invalid HTTP header names and values. (Pull #725)
* SECURITY FIX: Ensure path value is escaped before logging to the console. (Pull #724)
* Fix `--proxy-headers` client IP and host when using a Unix socket. (Pull #636)

## 0.11.6

* Fix overriding the root logger.

## 0.11.5

* Revert "Watch all files, not just .py" due to unexpected side effects.
* Revert "Pass through gunicorn timeout config." due to unexpected side effects.

## 0.11.4

* Use `watchgod`, if installed, for watching code changes.
* Watch all files, not just .py.
* Pass through gunicorn timeout config.

## 0.11.3

* Update dependencies.

## 0.11.2

* Don't open socket until after application startup.
* Support `--backlog`.

## 0.11.1

* Use a more liberal `h11` dependency. Either `0.8.*` or `0.9.*``.

## 0.11.0

* Fix reload/multiprocessing on Windows with Python 3.8.
* Drop IOCP support. (Required for fix above.)
* Add `uvicorn --version` flag.
* Add `--use-colors` and `--no-use-colors` flags.
* Display port correctly, when auto port selection isused with `--port=0`.

## 0.10.8

* Fix reload/multiprocessing error.

## 0.10.7

* Use resource_sharer. DupSocket to resolve socket sharing on Windows.

## 0.10.6

* Exit if `workers` or `reload` are use without an app import string style.
* Reorganise supervisor processes to properly hand over sockets on windows.

## 0.10.5

* Update uvloop dependency to 0.14+

## 0.10.4

* Error clearly when `workers=<NUM>` is used with app instance, instead of an app import string.
* Switch `--reload-dir` to current working directory by default.

## 0.10.3

* Add ``--log-level trace`

## 0.10.2

* Enable --proxy-headers by default.

## 0.10.1

* Resolve issues with logging when using `--reload` or `--workers`.
* Setup up root logger to capture output for all logger instances, not just `uvicorn.error` and `uvicorn.access`.

## 0.10.0

* Support for Python 3.8
* Separated out `uvicorn.error` and `uvicorn.access` logs.
* Coloured log output when connected to a terminal.
* Dropped `logger=` config setting.
* Added `--log-config [FILE]` and `log_config=[str|dict]`. May either be a Python logging config dictionary or the file name of a logging configuration.
* Added `--forwarded_allow_ips` and `forwarded_allow_ips`. Defaults to the value of the `$FORWARDED_ALLOW_IPS` environment variable or "127.0.0.1". The `--proxy-headers` flag now defaults to `True`, but only trusted IPs are used to populate forwarding info.
* The `--workers` setting now defaults to the value of the `$WEB_CONCURRENCY` environment variable.
* Added support for `--env-file`. Requires `python-dotenv`.
