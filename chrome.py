#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# (C) Copyright: Profound Networks, LLC 2017
#
"""Implements the Chrome backend.


To enable all features, please install our fork of pychrome:

- `GitHub repo <https://github.com/ProfoundNetworks/pychrome>`__
- `Package <s3://dbi2-ue2/software/pychrome-latest.tar.gz>`__

How to install the fork::

    aws s3 cp s3://dbi2-ue2/software/pychrome-latest.tar.gz pychrome.tar.gz
    pip install pychrome.tar.gz

Downloads Web pages given their URL using Google's headless Chrome.
Renders dynamic content such as JavaScript, closely mirroring what a human user
would see if they visited the URL.

Main entry points:

- :py:func:`optional_chrome_support`
- :py:func:`setup`
- :py:func:`teardown`

Example usage::

    import chrome
    with chrome.optional_chrome_support():
        page = retrieve('http://profound.net')

Alternatively::

    import chrome
    pid = chrome.setup()
    page = chrome.retrieve('http://profound.net')
    chrome.teardown(pid)

Finally, the :py:func:`get_pid` function will return the PID of a running
Chrome subprocess.

This module has no strict DBI2 dependencies.  You may copy it to other projects
and it will still work, provided the required libraries are still available.

Influential environment variables:

- set ``GECKO_CHROME_DEBUG=1`` to enable debugging.
- set ``GECKO_USE_EVASIONS=1`` to enable `bot detection evasions <https://github.com/berstend/
  puppeteer-extra/tree/master/packages/puppeteer-extra-plugin-stealth/evasions>`__
"""

import argparse
import collections
import contextlib
import dataclasses
import json
import logging
import os
import os.path as P
import socket
import subprocess
import sys
import time
import re
import threading
import urllib.parse

from functools import partial

import psutil
import pychrome
import requests
import tldextract
import websocket

from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
)

exchange: Optional[Any] = None

#
# Allow this module to be stand-alone and work without dbi2.gecko.
#
try:
    from dbi2.gecko import config
except ImportError:
    exchange = None
    _DEFAULT_CHROME_PORT = 9222
    _CHROME_USER_AGENT = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36"
    )
    _CHROME_DIR = '/tmp/google-chrome'
    _PAGE_TIMEOUT = 15
    _PROXY = None
else:
    _DEFAULT_CHROME_PORT = config.CONFIG.chrome_port  # type: ignore
    _CHROME_USER_AGENT = config.CONFIG.user_agent  # type: ignore
    _CHROME_DIR = config.CONFIG.chrome_dir  # type: ignore
    _PAGE_TIMEOUT = config.CONFIG.page_timeout  # type: ignore
    _PROXY = config.CONFIG.proxy  # type: ignore

try:
    from dbi2.gecko import exchange
except ImportError:
    class _DummyExchange:
        def report_error(self, *args, **kwargs):  # skipcq: PYL-R0201
            return False
    exchange = _DummyExchange()

try:
    from dbi2.gecko.retriever import Result
except ImportError:
    @dataclasses.dataclass
    class Result:  # type: ignore
        url: str
        redirected_url: str = ''
        tld: str = ''
        status_code: Optional[int] = None
        network_error: str = ''
        headers: Dict[str, Any] = dataclasses.field(default_factory=dict)
        html: str = ''
        all_net_reply: Dict[str, Any] = dataclasses.field(default_factory=dict)
        cookies: List[Any] = dataclasses.field(default_factory=list)
        timer: float = 0
        extra: Dict = dataclasses.field(default_factory=dict)


CHROME_CACHE_PATH = P.join(_CHROME_DIR, "Default")

_CHROME_EXE_PATH = os.environ.get('CHROME_EXE', 'google-chrome-stable')

_LOGGER = logging.getLogger(__name__)
_LOGGER.addHandler(logging.NullHandler())

_API_TIMEOUT = 10
"""Timeout for API calls to the headless Chrome."""
_CACHE_SIZE = 2500 * 10 ** 6  # 100MB
_MEDIA_CACHE_SIZE = 2500 * 10 ** 6  # 100MB
_NULL = open(os.devnull, 'w')
_WATCHER_PERIOD = 20
"""The duration between Chrome watcher runs, in seconds"""

_HTTP_DEBUG_URL = "http://127.0.0.1:{port}/json".format(port=_DEFAULT_CHROME_PORT)
"""Headless chrome exposes information about opened tabs via this URL"""

_WEBSOCKET_URL = "ws://127.0.0.1:{port}/devtools/page/".format(port=_DEFAULT_CHROME_PORT)
"""Headless chrome uses websockets to talk to the tabs."""

_TAB_LIFETIME = 75
"""The maximum lifetime of a single Chrome tab, in seconds.

Should be greater than the page timeout.
Also, should take into account the worst case scenario, where each API call
to Chrome takes seconds to respond. We don't want to kill a running tab prematurely.
"""
_CONTEXT_LIFETIME = 96
"""The maximum lifetime of a single Chrome browser context, in seconds."""

_CONTENT_TYPE_PATTERN = re.compile('content-type', re.IGNORECASE)

_VALID_CONTENT_TYPES = {'text/css', 'application/javascript', 'text/html', 'text/plain'}
"""
Chrome DevTools Protocol requires extra call to retrieve response body (Network.getResponseBody)
To reduce the number of unnecessary queries, we are whitelisting content-types that we actually
care about and want to retrieve body of the associated response.
"""

_MEDIA_EXTENSIONS = [
    '*.mp4', '*.webm', '*.mpeg',
]
"""
We don't want to make requests for media files to save network bandwith, speedup
page load time and save cache space.
"""

_ADDRESS_ALREADY_IN_USE_ERROR = 48
_ADDRESS_ALREADY_BOUND_ERROR = 98

_CHROME_STARTUP_TIME = 3

_MIN_PAGE_WAIT = 1.5
"""The minimum amount of time in seconds to wait for page loading.

We do this to handle events from pages that contain meta-refresh redirects.
"""

_IS_DARWIN = os.uname()[0] == 'Darwin'

_CERTIFICATE_ERROR_PREFIX = "net::ERR_CERT"
"""Errors related to the invalid HTTPS certificate reported by Chrome starts with this prefix"""

_CERTIFICATE_ERROR_TEXT = "https certificate error"
"""Text that should be displayed in case of HTTPS certificate error"""

_GENERAL_CHROME_EXCEPTION = "chrome error"

_WINDOW_OPEN_OVERRIDE = """
window.popups_count = 0;
window.open = function(url, name, features) {
    window.popups_count += 1;
};
"""
_GET_DOCUMENT_HTML = "(document.doctype ?" \
                     "new XMLSerializer().serializeToString(document.doctype) : '')" \
                     "+ document.documentElement.outerHTML;"
"""
The document.documentElement.outerHTML doesn't include HTML DOCTYPE,
so we retrieve it from the document.doctype.
"""

_DEBUG = os.environ.get('GECKO_CHROME_DEBUG', False)
_USE_EVASIONS = os.environ.get('GECKO_USE_EVASIONS', False)
"""When set, applies various evasion techniques to make detection of headless Chrome harder.

https://github.com/berstend/puppeteer-extra/tree/master/packages/extract-stealth-evasions
"""

_EXTRA_JS = ""
if _USE_EVASIONS:
    evasions_path = P.join(P.dirname(P.abspath(__file__)), 'stealth.min.js')
    if P.exists(evasions_path):
        _LOGGER.debug('Using JS evasions to avoid bot detection.')
        _EXTRA_JS = open(evasions_path, 'rt').read()
    else:
        _LOGGER.warning("Can't use evasions, %r file does not exist." % evasions_path)

_CHROME_WATCHER_SLEEP = 1
_CHROME_WAIT_ATTEMPTS = 10
_CHROME_WS_ID = 1
"""The label that's used when sending WebSocket requests.

When sending requests to WebSocket API, we need to provide a label for our request.
It's possible to send multiple requests and receive multiple unordered responses.
Each WebSocket response contains the request ID.

Since we don't send multiple requests over one WebSocket connection, we can use the same ID
everywhere.
"""

_PAGE_LOADED_EVENT = 'load'
"""
The following events are supported::
   * load: when load event is fired.
   * DOMContentLoaded: when the DOMContentLoaded event is fired.
   * networkIdle: when there are no more network connections
"""


def _get_tld(url: str) -> str:
    assert url.lower().startswith('http'), 'input must be a URL, not a hostname: %s' % url
    netloc = urllib.parse.urlparse(url).netloc
    return tldextract.extract(netloc).suffix


def _close_tab(tab_id: str, timeout: int = _API_TIMEOUT, terminate: bool = False) -> None:
    """Close a tab.

    :param tab_id: The ID of a tab.
    :param timeout: The timeout for request in seconds.
    :param terminate: Send an API call to terminate JavaScript execution in case of an error.
    """
    try:
        requests.get('%s/close/%s' % (_HTTP_DEBUG_URL, tab_id), timeout=timeout)
    except Exception as err:
        _LOGGER.error('unable to close tab:', err)
        if terminate:
            _terminate_tab_execution_ws(tab_id, timeout=timeout)


def _terminate_tab_execution_ws(tab_id: str, timeout: int = _API_TIMEOUT) -> None:
    """Stop JavaScript execution for the specified tab.

    Uses WebSockets and fails silently.
    """
    try:
        ws = websocket.create_connection(_WEBSOCKET_URL + tab_id)
        ws.settimeout(timeout)
        ws.send(json.dumps({
            "method": "Runtime.terminateExecution", "params": {},
            "id": _CHROME_WS_ID}
        ))
        ws.recv()
        ws.close()
    except Exception as err:
        _LOGGER.debug("Can't terminate tab: %s", err)


def _check_unclosed_tabs(
        tabs_registry: Optional[Dict] = None,
        timeout: int = _WATCHER_PERIOD,
        max_tab_lifetime: int = _TAB_LIFETIME,
) -> Optional[Dict]:
    """Closes tabs that were not closed because of the failed API calls and runslave killer."""

    if tabs_registry is None:
        tabs_registry = collections.defaultdict(time.time)

    response = requests.get(_HTTP_DEBUG_URL, timeout=timeout)

    if response.status_code != requests.codes.OK:
        _LOGGER.error(response.content)
        return tabs_registry

    active_tab_ids = {tab['id'] for tab in response.json()}

    for tab_id in list(tabs_registry.keys()):
        if tab_id not in active_tab_ids:
            tabs_registry.pop(tab_id)

    for tab_id in active_tab_ids:
        if time.time() - tabs_registry[tab_id] >= max_tab_lifetime:
            _LOGGER.debug('Closing tab: %s', tab_id)
            _close_tab(tab_id, timeout=timeout, terminate=True)

    return tabs_registry


def _get_debug_websocket_url() -> str:
    r = requests.get("%s/version" % _HTTP_DEBUG_URL)
    r.raise_for_status()
    version_data = r.json()
    return version_data['webSocketDebuggerUrl']


def _get_opened_contexts(timeout: int = _API_TIMEOUT) -> Optional[Any]:
    ws_url = _get_debug_websocket_url()
    ws = websocket.create_connection(ws_url)
    ws.settimeout(timeout)
    ws.send(json.dumps({"method": "Target.getBrowserContexts", "params": {}, "id": _CHROME_WS_ID}))
    data = json.loads(ws.recv())
    ws.close()
    if data['id'] != _CHROME_WS_ID:
        _LOGGER.error("Received wrong response ID: %r", data)
        return None
    return data.get('result', {}).get("browserContextIds", None)


def _close_context(context_id: str, timeout: int = _API_TIMEOUT) -> None:
    ws_url = _get_debug_websocket_url()
    ws = websocket.create_connection(ws_url)
    ws.settimeout(timeout)
    ws.send(json.dumps({
        "method": "Target.disposeBrowserContext",
        "params": {"browserContextId": context_id},
        "id": _CHROME_WS_ID
    }))
    ws.recv()
    ws.close()


def _check_unclosed_contexts(
        contexts_registry: Optional[Dict] = None,
        timeout: int = _WATCHER_PERIOD,
        max_context_lifetime: int = _CONTEXT_LIFETIME,
) -> Optional[Dict]:
    """Disposes contexts that were not closed because of the failed API calls."""

    if contexts_registry is None:
        contexts_registry = collections.defaultdict(time.time)
    try:
        active_contexts = set(_get_opened_contexts(timeout))  # type: ignore
    except Exception as err:
        _LOGGER.debug("Can't list browser contexts: %s", err)
        return contexts_registry

    if active_contexts is None:
        return

    for context_id in list(contexts_registry.keys()):
        if context_id not in active_contexts:
            contexts_registry.pop(context_id)

    for context_id in active_contexts:
        if time.time() - contexts_registry[context_id] >= max_context_lifetime:
            _LOGGER.debug('Closing browser context: %s', context_id)
            try:
                _close_context(context_id, timeout=timeout)
            except Exception as err:
                _LOGGER.debug("Can't dispose browser context: %s", err)

    return contexts_registry


def watcher_thread() -> None:
    """Continuously monitor the health of the headless Chrome program.

    Closes inactive tabs.
    When running on an EC2 instance, reboots the instance if Chrome is no longer running.

    This function never exits, so call it from its own daemon thread.
    """
    import dbi2.client
    from dbi2.gecko import awsutils

    if dbi2.client.get_current_instance_id() is None:
        # don't run this thread outside of EC2 instance
        return

    #
    # Sometimes Chrome needs 2-3 seconds to perform a cold start.
    # We need to be sure that Chrome and all its services are running before running the daemon,
    # otherwise the instance will be restarted by the watcher loop.
    #
    for _ in range(_CHROME_WAIT_ATTEMPTS):
        if test_port():
            break
        time.sleep(_CHROME_WATCHER_SLEEP)
    else:
        _LOGGER.critical('initial startup of Chrome has failed')

    n_timed_out = 0
    active_tabs = None
    active_contexts = None

    while True:
        if not test_port():
            _LOGGER.critical("Chrome died, I'm rebooting now")
            awsutils.reboot_machine()
            break
        #
        # If an API request timed out more than three times in a row, reboot the instance.
        # Sometimes instead of crashing Chrome just hangs.
        #
        if n_timed_out > 3:
            _LOGGER.critical(
                "Chrome API is not available for more than a minute, I'm rebooting now"
            )
            awsutils.reboot_machine()
            break

        try:
            active_tabs = _check_unclosed_tabs(active_tabs, timeout=_WATCHER_PERIOD)
        except requests.Timeout:
            n_timed_out += 1
            continue
        except Exception as err:
            _LOGGER.exception(err)

        try:
            active_contexts = _check_unclosed_contexts(active_contexts, timeout=_WATCHER_PERIOD)
        except Exception as err:
            _LOGGER.exception(err)

        n_timed_out = 0
        time.sleep(_WATCHER_PERIOD)


def get_tabs_opened() -> Optional[List[str]]:
    """Return a list of opened tabs.

    :returns: A URL for each open tab, or None in case of error
    """
    try:
        response = requests.get(_HTTP_DEBUG_URL)
    except requests.ConnectionError:
        return None
    if response.status_code == requests.codes.OK:
        return [tab['url'] for tab in response.json()]
    return None


def get_chrome_cache_size() -> Optional[str]:
    """Return the size of cache.

    :returns: The size of the cache, or None in case of an error.

    Example output::
        56K
    """
    try:
        return subprocess.check_output(['du', '-sh', CHROME_CACHE_PATH]).split()[0].decode('utf-8')
    except subprocess.CalledProcessError:
        return None


def get_metrics() -> dict:
    """Return metrics for a running Chrome instance.

    :returns: A dictionary containing metrics.

    Example output::
        {"cache_size": "56K",
         "memory_percent": [0.5, 0.5,], "cpu_percent": [0.5, 0.5],
         "tabs_opened": [1, ["about:blank"]]}
    """
    metrics = collections.defaultdict(list)
    for process in psutil.process_iter(('pid', 'name')):
        if 'chrome' not in process.name():
            continue
        metrics['cpu_percent'].append(process.cpu_percent())
        metrics['memory_percent'].append(process.memory_percent())
    tabs = get_tabs_opened()
    metrics['tabs_opened'] = [len(tabs) if tabs else -1, tabs]
    metrics['cache_size'] = get_chrome_cache_size()  # type: ignore
    return dict(metrics)


class ChromeException(Exception):
    """Used for custom Chrome exceptions."""


def _get_pidinfo(port: int = _DEFAULT_CHROME_PORT) -> List[psutil.Process]:
    """Return all processes listening on a specific port."""
    if _IS_DARWIN:
        #
        # The psutil.net_connections() code won't work on MacOS unless you
        # are root.
        #
        # https://github.com/Lynten/stanford-corenlp/issues/26
        #
        return []

    return [ps for ps in psutil.net_connections() if ps.laddr.port == port]


def setup(port: int = _DEFAULT_CHROME_PORT) -> int:
    """Run headless Chrome on the specified port.

    If Chrome is already running on that port, returns the existing PID.

    :param port: The port to run Chrome on.
    :returns: The PID of the headless Chrome process.

    """
    chrome_pid = get_pid(port=port)

    if chrome_pid:
        _LOGGER.debug("Reusing existing chrome connection (PID: %r)", chrome_pid)
        #
        # We sleep here in case that PID is still starting up.  TODO: we could
        # check how long it's been running and sleep conditionally.
        #
        time.sleep(_CHROME_STARTUP_TIME)
        return chrome_pid

    _LOGGER.debug('no existing chrome instances running')

    #
    # For more information, please see:
    # https://peter.sh/experiments/chromium-command-line-switches/
    #
    cmd = [
        _CHROME_EXE_PATH,
        '--headless',
        '--remote-debugging-port={}'.format(port),
        '--user-agent={}'.format(_CHROME_USER_AGENT),
        #
        # Browse Without Signing In.
        #
        '--bwsi',
        #
        # Limit the size of the cache. Recent versions of Chrome tend to ignore this
        # directive when there is a lot of free space on the machine.
        #
        '--disk-cache-size={}'.format(_CACHE_SIZE),
        '--media-cache-size={}'.format(_MEDIA_CACHE_SIZE),
        '--aggressive-tab-discard',
        #
        # Disable various background network services, including extension updating,
        # safe browsing service, upgrade detector, translate, User Metrics Analysis.
        #
        '--disable-component-update',
        '--safebrowsing-disable-auto-update',
        #
        # This flag is temporary disabled to test how it affects performance.
        # https://github.com/cypress-io/cypress/issues/1320
        #
        # '--disable-background-networking',
        #
        # Do not use GPU rendering
        #
        '--disable-gpu',
        #
        # Do no report crashes or any other problems to Google.
        #
        '--disable-breakpad',
        '--disable-domain-reliability',
        #
        # Don't slow down non-active (background) tabs. While gathering, Chrome is constantly
        # switching between tabs. We want to have a uniform priority for all opened tabs.
        #
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding',
        #
        # Disable Page is unresponsive popup. Some pages can recover from unresponsiveness and
        # we want to complete gathering them.
        #
        '--disable-hang-monitor',
        #
        # Speeds up tab closing by running a tab's onunload js handler independently of the GUI.
        #
        '--enable-fast-unload',
        #
        # Disables password saving UI, default browser check prompt and some animations.
        #
        '--enable-automation',
        #
        # Set window size to the most common resolution.
        #
        '--window-size=1366x768',
        #
        # Prevent Chrome from using system keychain for passwords. Our crawler does not store any
        # passwords, but using keychain sometimes require sudo access.
        #
        '--password-store=basic',
        '--use-mock-keychain',
        #
        # Ignore SSL and security errors. This allows us to crawl pages with expired certificates.
        #
        '--allow-running-insecure-content',
        '--ignore-certificate-errors',
        '--ignore-ssl-errors=yes',
        '--ignore-certifcate-errors-spki-list',
        #
        # Ignore phishing errors
        #
        '--disable-client-side-phishing-detection',
        #
        # Skip first run wizards.
        #
        '--no-first-run',
    ]
    if not _USE_EVASIONS:
        cmd.extend([
            #
            # These are here to reduce memory and CPU consumption of the Chrome processes.
            # We don't need that features at all.
            #
            '--disable-sync',
            '--disable-translate',
            '--disable-default-apps',
            '--disable-extensions',
            '--disable-notifications',
            '--disable-desktop-notifications',
            '--disable-webgl',
            '--disable-reading-from-canvas',
            '--mute-audio',
            '--disable-audio-output',
            #
            # Disable “Confirm Form Resubmission” popups.
            #
            '--disable-prompt-on-repost',
            #
            # Do not download images
            #
            '--blink-settings=imagesEnabled=false',
            #
            # Don't download any remote fonts and fallback to default ones.
            #
            '--disable-remote-fonts',
            #
            # Don't automatically render video
            #
            '--autoplay-policy=user-gesture-required',
            #
            # Puppeteer uses this to prevent some bugs in the headless mode.
            #
            '--disable-features=TranslateUI,BlinkGenPropertyTrees',

            #
            # The below arguments seem to improve Chrome performance under highload
            #
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--no-zygote',
        ])

    if _PROXY:
        cmd.append('--proxy-server=%s' % _PROXY)

    #
    # The build.sh for our Dockerfile ensures the file will be there
    #
    if P.isfile('/etc/running-inside-docker-container'):
        #
        # By default, Docker runs a container with a /dev/shm shared memory space 64MB.
        # This is typically too small for Chrome and will cause Chrome to crash when
        # rendering large pages.
        #
        cmd.append('--disable-dev-shm-usage')

    if _DEBUG:
        cmd.remove('--headless')

    if not _DEBUG:
        #
        # For some reason, when the user-data-dir parameter is specified,
        # Chrome does not invalidate some of the caches.
        #
        # It's not a big deal when gathering on EC2 instances because we don't gather
        # the same page more than one time and they don't change that frequently.
        #
        cmd.append('--user-data-dir={}'.format(_CHROME_DIR))
    #
    # Chrome is very verbose.  We don't want it polluting our systemd logs.
    # We should probably store the logs somewhere else instead of just
    # trashing them, though.
    #
    if _DEBUG:
        chrome_sub = subprocess.Popen(cmd)
    else:
        chrome_sub = subprocess.Popen(cmd, stdout=_NULL, stderr=subprocess.STDOUT)

    version = subprocess.check_output([_CHROME_EXE_PATH, '--version']).decode().strip()
    _LOGGER.debug("Creating new chrome connection (%s)", version)
    _LOGGER.debug("cmd: %r", cmd)

    time.sleep(_CHROME_STARTUP_TIME)
    return chrome_sub.pid


@contextlib.contextmanager
def optional_chrome_support(
        use_chrome: bool = True,
        port: int = _DEFAULT_CHROME_PORT,
) -> Iterator[None]:
    """A context manager that sets up and tears down headless Chrome, if it is needed.

    :param use_chrome: If True, runs Chrome.  If False, does nothing.
    :param port: The port number to run Chrome on.

    """
    if use_chrome:
        chrome_pid = setup(port)

    yield

    if use_chrome:
        teardown(chrome_pid)


def teardown(pid: int) -> None:
    """Shuts down headless Chrome by killing its subprocess.

    :param pid: The PID of the headless Chrome process.

    """
    p = psutil.Process(pid)
    p.kill()


def _parametrized_decorator(dec: Callable) -> Callable:
    """Decorator for decorators that allows to pass arguments to the decorator
    https://stackoverflow.com/a/26151604/5616580"""
    def layer(*args, **kwargs):
        def repl(f):
            return dec(f, *args, **kwargs)
        return repl
    return layer


@_parametrized_decorator
def _retry(func: Callable, times: int = 1, exception: Any = Exception):
    """Decorator that allows to retry decorated function multiple times
    if specified error occurred"""
    def inner(*args, **kwargs):
        error = ""
        for _ in range(times):
            try:
                return func(*args, **kwargs)
            except exception as e:
                error = e
                continue
        raise exception("%s: exceeded max number (%s) of retries. "
                        "Original message: '%s'" % (func.__name__, times, error))
    return inner


def _lock_page_state(func: Callable) -> Callable:
    """
    Decorator to make sure that only one handler can be modifying page_state at
    given time.
    """
    def func_wrapper(*args, **kwargs):
        kwargs["page_state"].lock.acquire()
        func(*args, **kwargs)
        kwargs["page_state"].lock.release()
    return func_wrapper


class PageState:
    """This data holder contains state information for a page being loaded.

    This information can be conceptually divided into several segments:

    1. input: accepted by this module
    2. internal: used by the implementation for housekeeping, etc
    3. output: for consumption by the rest of the application

    Input:

    :param str requested_url: The original URL to load

    Internal:

    :param int main_request_id: An internal ID that corresponds to the main request.
    :param dict all_responses: All received responses keyed by their corresponding request IDs.
    :param dict redirected_responses: Keys are URLs, values are response headers.
    :param threading.Event page_completely_loaded: Set when the page load is
        really complete, i.e. all resources and AJAX requests have completed loading.
    :param set requests_in_progress: Contains IDs of requests currently in progress.
    :param float page_load_started: When the request to load the page was made. Unix timestamp.
    :param float page_load_ended: When the request to load the page completed. Unix timestamp.
    :param boolean is_first: A flag that we use to identify the "main" request
        and frame.  These correspond to the first ever outgoing request.
    :param bool start_checking_pending_requests:
    :param threading.Lock lock: A mutex for ensuring safe access to this object
        from multiple threads.
    :param boolean main_request_failed:
    :param int main_frame_id:

    Output:

    :param str redirected_url: The final URL that got loaded.  May be different
        to the input url if we got redirected along the way.
    :param boolean error_403: For compatibility with legacy WebKit.
    :param str network_error:
    :param int popups_count:

    """
    def __init__(self, url: str):
        self.requested_url = url

        self.main_request_id = 0
        self.requests_dict: collections.defaultdict = collections.defaultdict(dict)
        self.all_responses: Dict[int, Any] = {}
        self.redirected_responses: Dict[int, Any] = {}
        self.page_completely_loaded_event = threading.Event()
        self.requests_in_progress: Set = set()
        self.page_load_started: Optional[float] = None
        self.page_load_ended: Optional[float] = None
        self.is_first = True
        self.start_checking_pending_requests = False
        self.lock = threading.Lock()
        self.main_request_failed = False
        self.main_frame_id = 0

        self.redirected_url = ""
        self.error_403 = False
        self.network_error = ""
        self.popups_count = 0

        self.status_code: Optional[int] = None


@_lock_page_state
def _page_lifecycle_handler(page_state: PageState, *args: Any, **kwargs: Any) -> None:
    """
    Function triggered on `Page.loadEventFired` event. At this point we check
    if there are any pending AJAX calls.
    """

    if kwargs.get('frameId', '') != page_state.main_frame_id:
        return
    if kwargs.get('name') != _PAGE_LOADED_EVENT:
        return
    page_state.start_checking_pending_requests = True
    if len(page_state.requests_in_progress) == 0:
        page_state.page_completely_loaded_event.set()


@_lock_page_state
def _frame_navigated_handler(page_state: PageState, *args: Any, **kwargs: Any) -> None:
    """Handle a `Page.frameNavigated` event.

    This event generally means that "some frame" got refreshed or navigated
    somewhere.  The frame does not necessarily have to be the "main" frame:
    e.g. iframes may cause these events to fire, too.

    The event gets fired once navigation of the frame has completed. The frame
    is now associated with the new loader.
    """
    #
    # Chrome reports every frame and iframe navigation,
    # we only need to keep track of the main frame that represents our page.
    # The other frames are irrelevant for our application.
    # Some child frames have a parentId set: they are also irrelevant, and we ignore them.
    #
    if 'frame' not in kwargs:
        return
    frame = kwargs['frame']

    if not frame.get('parentId') and frame.get('id'):
        #
        # We replicate the same logic as in the pyppeteer/puppeteer:
        #
        #   "Update frame id to retain frame identity on cross-process navigation."
        #
        page_state.main_frame_id = frame.get('id')

    if frame.get('id', "") != page_state.main_frame_id or frame.get('parentId', ""):
        return

    #
    # If the main frame navigated that means the page got redirected somewhere else or refreshed.
    #
    #
    # NB. The final destination can also be tracked by using Target.setDiscoverTargets and
    # Target.targetInfoChanged events.
    #
    page_state.redirected_url = frame['url']

    #
    # Check response code of the page after main frame navigated.
    # The response gets saved in a separate callback (_response_received) so
    # there is a small possibility that it has not been saved yet.  While this
    # is a race condition, it happens relatively rarely, so we accept it.
    #
    response = page_state.all_responses.get(frame['loaderId'])
    if response is None:
        _LOGGER.error('response is None, unable to update page_state.network_error')
        return

    status_code = response['response']['status']
    page_state.error_403 = status_code == 403
    page_state.status_code = status_code
    if status_code >= 400 or status_code < 200:
        page_state.network_error = str(status_code)


@_lock_page_state
def _navigated_within_document(page_state: PageState, **kwargs: Any) -> None:
    #
    # Fired when same-document navigation happens, e.g. due to history API usage
    # or anchor navigation.
    # We need this to keep track of SPAs: https://en.wikipedia.org/wiki/Single-page_application
    #
    if page_state.main_frame_id == kwargs.get("frameId") and kwargs.get("url"):
        page_state.redirected_url = kwargs.get("url")  # type: ignore


@_lock_page_state
def _request_will_be_sent(page_state: PageState, **kwargs: Any) -> None:
    """
    Function triggered on `Network.requestWillBeSent` event.
    """
    request_id = kwargs['requestId']
    request_url = kwargs['request']['url']
    page_state.requests_dict[request_id][request_url] = kwargs
    page_state.requests_in_progress.add(request_id)
    if request_id == page_state.main_request_id:
        page_state.redirected_url = request_url

    if page_state.is_first:
        page_state.main_request_id = request_id
        page_state.main_frame_id = kwargs['frameId']
        page_state.is_first = False

    if "redirectResponse" in kwargs:
        resp = kwargs["redirectResponse"]
        page_state.redirected_responses[resp["url"]] = resp['headers']


@_lock_page_state
def _response_received(page_state: PageState, **kwargs: Any) -> None:
    """
    Function triggered on `Network.responseReceived` event.
    """
    page_state.all_responses[kwargs['requestId']] = kwargs
    #
    # Requests that belong to frames don't trigger Network.loadingFinished,
    # so we duplicate the logic here as well.
    #
    page_state.requests_in_progress.discard(kwargs['requestId'])
    if len(page_state.requests_in_progress) == 0 and page_state.start_checking_pending_requests:
        page_state.page_completely_loaded_event.set()


@_lock_page_state
def _loading_failed(page_state: PageState, **kwargs: Any) -> None:
    if kwargs['type'] == 'Document':
        _LOGGER.error(f'loading {page_state.requested_url} failed: {kwargs["errorText"]}, {kwargs}')
        if kwargs["requestId"] == page_state.main_request_id:
            page_state.main_request_failed = True
            page_state.network_error = kwargs["errorText"]
            page_state.page_completely_loaded_event.set()
    page_state.requests_dict.pop(kwargs['requestId'], None)
    page_state.requests_in_progress.discard(kwargs['requestId'])


@_lock_page_state
def _loading_finished(page_state: PageState, **kwargs: Any) -> None:
    page_state.requests_in_progress.discard(kwargs['requestId'])
    if len(page_state.requests_in_progress) == 0 and page_state.start_checking_pending_requests:
        page_state.page_completely_loaded_event.set()


def _page_interstitial_shown(tab: pychrome.Tab, **kwargs: Any) -> None:
    tab.call_method("Page.stopLoading", _timeout=_API_TIMEOUT)


def _handle_dialogs(tab: pychrome.Tab, **kwargs: Any) -> None:
    tab.call_method("Page.handleJavaScriptDialog", accept=True, promptText="",
                    _timeout=_API_TIMEOUT)


def _handle_page_crash(page_state: PageState, **kwargs: Any) -> None:
    page_state.main_request_failed = True
    page_state.network_error = "Page crashed."
    page_state.page_completely_loaded_event.set()


@_retry(times=3, exception=requests.exceptions.ReadTimeout)
def setup_browser(
        port: int,
        timeout: Optional[int] = None,
        isolate_tabs: bool = False,
) -> Tuple[pychrome.Browser, pychrome.Tab]:
    """
    Setup a new Browser session and open a new tab.
    Under the high load Chrome might not be responding quickly enough.
    By retrying on timeout error, we're giving this page another chance to be crawled.

    When ``isolate_tabs`` is enabled, creates a new tab that uses its own storage for cookies, cache
    and so on. Similar to an incognito profile but allows to have more than one. Note that this
    feature consumes more RAM, CPU and storage.

    :param port: The port on which browser runs.
    :param timeout: The API calls timeout in seconds.
    :param isolate_tabs: If True, will isolate the new tab from other tabs.
    """
    browser = pychrome.Browser(url="http://127.0.0.1:{}".format(port))

    if isolate_tabs and not hasattr(browser, 'new_private_tab'):
        _LOGGER.warning("Can't isolate the new tab, please install a fork of pychrome. "
                        "s3://dbi2-ue2/software/pychrome.tar.gz")
        isolate_tabs = False

    if isolate_tabs:
        tab = browser.new_private_tab(timeout=timeout)
    else:
        tab = browser.new_tab(timeout=timeout)
    return browser, tab


def _attach_listeners(tab: pychrome.Tab, page_state: PageState) -> None:
    """
    Attach handlers to the relevant devtools protocol events.
    """
    def with_page_state(function):
        return partial(function, page_state=page_state)

    tab.set_listener("Network.requestWillBeSent", with_page_state(_request_will_be_sent))
    tab.set_listener("Network.responseReceived", with_page_state(_response_received))
    tab.set_listener("Page.lifecycleEvent", with_page_state(_page_lifecycle_handler))
    tab.set_listener("Page.frameNavigated", with_page_state(_frame_navigated_handler))
    tab.set_listener("Page.navigatedWithinDocument", with_page_state(_navigated_within_document))
    tab.set_listener("Inspector.targetCrashed", with_page_state(_handle_page_crash))

    tab.set_listener("Network.loadingFailed", with_page_state(_loading_failed))
    tab.set_listener("Network.loadingFinished", with_page_state(_loading_finished))
    tab.set_listener("Page.interstitialShown", partial(_page_interstitial_shown, tab=tab))
    tab.set_listener("Page.javascriptDialogOpening", partial(_handle_dialogs, tab=tab))


@_retry(times=2, exception=pychrome.TimeoutException)
def _enable_relevant_protocol_domains(tab: pychrome.Tab) -> None:
    #
    # Timeouts in this function happen very rarely, so it's ok to retry
    # the whole function in case of a timeout error.
    #
    tab.call_method("Network.enable", _timeout=_API_TIMEOUT)
    tab.call_method("Page.enable", _timeout=_API_TIMEOUT)
    tab.call_method("Runtime.enable", _timeout=_API_TIMEOUT)
    tab.call_method("Page.setAdBlockingEnabled", enabled=False, _timeout=_API_TIMEOUT)
    tab.call_method("Page.setLifecycleEventsEnabled", enabled=True, _timeout=_API_TIMEOUT)
    tab.call_method("Network.setCacheDisabled", cacheDisabled=False, _timeout=_API_TIMEOUT)
    tab.call_method("Network.setBlockedURLs", urls=_MEDIA_EXTENSIONS, _timeout=_API_TIMEOUT)
    tab.call_method("Page.addScriptToEvaluateOnNewDocument", source=_WINDOW_OPEN_OVERRIDE,
                    _timeout=_API_TIMEOUT)
    if _EXTRA_JS:
        tab.call_method(
            "Page.addScriptToEvaluateOnNewDocument", source=_EXTRA_JS, _timeout=_API_TIMEOUT
        )
    tab.call_method("Security.setIgnoreCertificateErrors", ignore=True, _timeout=_API_TIMEOUT)


def _set_number_of_popups(page_state: PageState, tab: pychrome.Tab) -> None:
    result = tab.call_method("Runtime.evaluate", expression="window.popups_count",
                             _timeout=_API_TIMEOUT)
    if 'result' in result and result['result']['type'] == 'number':
        page_state.popups_count = result['result']['value']


def _stop_tab(tab: pychrome.Tab) -> None:
    """Stops JavaScript execution and network/tab loading."""
    try:
        tab.call_method("Runtime.terminateExecution", _timeout=_API_TIMEOUT)
        tab.call_method("Page.stopLoading", _timeout=_API_TIMEOUT)
    except pychrome.PyChromeException as err:
        _LOGGER.error("Can't stop tab: %s", err)


@_retry(times=2, exception=ChromeException)
def _perform_navigation(tab: pychrome.Tab, url: str, timeout: int) -> None:
    try:
        #
        # We use the page timeout here, because this call blocks until
        # Chrome receives a first HTTP response from the page.
        #
        result = tab.call_method("Page.navigate", url=url, _timeout=timeout)
        if result.get("errorText"):
            _LOGGER.error("Navigation to %s errored out: %r", url, result['errorText'])

    except pychrome.TimeoutException:
        #
        # We exclude the URL from the exception message intentionally, because
        # the exception messages will get grouped by the report module.
        #
        _LOGGER.error("Navigation to %s timed out", url)
        raise ChromeException("Navigation to website timed out.")


def _perform_request(tab: pychrome.Tab, timeout: int, page_state: PageState) -> None:
    page_state.page_load_started = time.time()
    tab.start()
    _enable_relevant_protocol_domains(tab)
    _perform_navigation(tab, page_state.requested_url, timeout)
    page_state.page_completely_loaded_event.clear()
    completed_loading = page_state.page_completely_loaded_event.wait(timeout)

    page_state.page_load_ended = time.time()
    time_left = _MIN_PAGE_WAIT - (page_state.page_load_ended - page_state.page_load_started)
    if time_left > 0:
        #
        # Some pages "load" suspiciously fast.  Often, they contain meta refreshes.
        # So, wait a little bit for the meta refresh to get handled properly, so we end
        # up at the final destination.
        #
        time.sleep(time_left)

    if not completed_loading:
        #
        # If a page wasn't loaded in time, it probably still loads some resources or executes
        # heavy JavaScript. If we don't stop JavaScript, we won't be able to retrieve
        # HTML in some cases.
        #
        _stop_tab(tab)


def _retrieve_cookies(tab: pychrome.Tab) -> List[Tuple[str, str]]:
    try:
        return tab.call_method("Page.getCookies", _timeout=_API_TIMEOUT).get('cookies', [])
    except pychrome.TimeoutException:
        #
        # For some reason, the Page.getCookies API call timeouts fairly often.
        # We don't want to skip the page because of it.
        #
        _LOGGER.error('Page.getCookies timed out')
        return []


def _get_all_net_reply(messages: Dict, page_state: PageState) -> Dict:
    result = {}
    for _, response in messages.items():
        url = response['response']['url']
        result[url] = response['response']['headers']
    result.update(page_state.redirected_responses)
    return result


def _teardown_browser(browser: pychrome.Browser, tab: pychrome.Tab) -> None:
    try:
        # it might be the same bug in pychrome library
        # https://github.com/GoogleChrome/puppeteer/issues/1490
        tab.call_method('Page.navigate', url='about:blank', timeout=_API_TIMEOUT)
        tab.stop()
        browser.close_tab(tab)
    except Exception as err:
        _LOGGER.error("Can't teardown a tab: %s. Trying a fallback method.", err)
        assert exchange
        exchange.report_error("Can't teardown a tab")
        #
        # As a last resort, manually send HTTP request that is supposed to kill the tab
        #
        _close_tab(tab.id, timeout=_API_TIMEOUT)


def _get_html_using_runtime(tab: pychrome.Tab, timeout: int) -> str:
    response = tab.call_method(
        "Runtime.evaluate",
        expression=_GET_DOCUMENT_HTML,
        timeout=timeout
    )
    if 'exceptionDetails' in response:
        #
        # We exclude the response from the exception message intentionally, because
        # the exception messages will get grouped by the report module.
        #
        _LOGGER.error("Can't retrieve DOM: %s", response)
        raise ChromeException("Can't retrieve DOM")
    return response["result"]["value"]


def _get_html_using_api(tab: pychrome.Tab, timeout: int, node_id: Optional[str] = None) -> str:
    if node_id is None:
        node = tab.call_method('DOM.getDocument', depth=0, pierce=False, _timeout=timeout)
        node_id = node['root']['nodeId']
    html = tab.call_method('DOM.getOuterHTML', nodeId=node_id, _timeout=timeout)
    return html['outerHTML']


def _get_html(tab: pychrome.Tab) -> str:
    """Serialize current DOM to the HTML markup.

    DOM serialization is computationally expensive,
    thus increasing timeout reduces the number of crawling errors
    when Chrome is under high load.
    """
    try:
        return _get_html_using_api(tab, timeout=_API_TIMEOUT)
    except (ChromeException, pychrome.PyChromeException):
        #
        # Something might be blocking DOM operations.
        #
        _stop_tab(tab)

        #
        # This method tends to be slightly faster and does the same thing using a single API call.
        # The downside of it is that Runtime calls can raise an unrelated exception under highload.
        #
        return _get_html_using_runtime(tab, timeout=_API_TIMEOUT)


def _gather_all_data(tab: pychrome.Tab, page_state: PageState) -> Result:
    tab.del_all_listeners()

    try:
        _set_number_of_popups(page_state, tab)
    except Exception as err:
        _LOGGER.error("Can't set the number of popups: %s", err)
        page_state.popups_count = 0
    try:
        #
        # N.B: Chrome automatically merges multiple headers with the same name
        #
        headers = page_state.all_responses[page_state.main_request_id]['response']['headers']
    except Exception as err:
        _LOGGER.exception(err)
        headers = {}

    # ip = page_state.all_responses[page_state.main_request_id]['response']['remoteIPAddress']

    assert page_state.page_load_ended and page_state.page_load_started
    time_delta = page_state.page_load_ended - page_state.page_load_started

    if page_state.redirected_url.startswith('chrome-error://'):
        raise ValueError("Chrome: Error Page")

    return Result(
        url=page_state.requested_url,
        redirected_url=page_state.redirected_url or page_state.requested_url,
        tld=_get_tld(page_state.redirected_url or page_state.requested_url),
        status_code=page_state.status_code,
        network_error=page_state.network_error,
        headers=headers,
        html=_get_html(tab),
        all_net_reply=_get_all_net_reply(page_state.all_responses, page_state),
        cookies=_retrieve_cookies(tab),
        timer=time_delta,
        extra={"popups_count": page_state.popups_count},
    )


def _get_error_result(url: str, error: Any) -> Result:
    error_message = _parse_error_message(error)
    return Result(url=url, network_error=str(error_message))


def _parse_error_message(error: str) -> str:
    assert exchange
    error_msg = str(error)
    exchange.report_error(error_msg)
    if error_msg.startswith(_CERTIFICATE_ERROR_PREFIX):
        error_msg = _CERTIFICATE_ERROR_TEXT
    return error_msg


def test_port(port: int = _DEFAULT_CHROME_PORT) -> bool:
    """Check if a specified port is already in use.

    :param port: The port to test.
    :return: True if the port is in use.

    Note:

    This alone is not sufficient to determine whether Chrome is running
    successfully, because a zombie Chrome process may be listening on the port.
    Typically, it takes the Chrome subprocess up to a minute to disappear
    completely after being killed: during this minute, the subprocess _still_
    listens on the port, but rejects all requests.

    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(('', port))  # Try to open port
    except (OSError, socket.error) as e:
        if e.errno in (_ADDRESS_ALREADY_BOUND_ERROR, _ADDRESS_ALREADY_IN_USE_ERROR):
            return True
        raise e
    s.close()
    return False


def get_pid(port: int = _DEFAULT_CHROME_PORT) -> Optional[int]:
    """Returns the PID of a running Chrome process listening on a specific port.

    :param port: The port to check.
    :returns: The PID or None.
    """
    if not test_port(port=port):
        _LOGGER.debug('nobody is listening on port %r', port)
        return None

    info = _get_pidinfo(port=port)
    for i in info:
        if i.pid is not None:
            return i.pid

    #
    # For some reason, google-chrome running inside a Docker container won't
    # show up in the above list.  Try looking for it manually.
    #
    # See /docker/chrome/README.md for more info.
    #
    containers = [
        c for c in psutil.process_iter(('cmdline', 'name'))
        if c.name() == 'docker' and 'chrome' in c.cmdline()
    ]
    try:
        return containers[0].pid
    except IndexError:
        pass

    _LOGGER.debug('%d zombie processes listening on port %r', len(info), port)
    return None


def retrieve(
        url: str,
        port: int = _DEFAULT_CHROME_PORT,
        timeout: int = _PAGE_TIMEOUT,
        isolate_tabs: bool = False,
) -> Result:
    """Retrieve a specified URL.

    Expects that Chrome is already running on the specified port.
    Stops page loading and returns partially loaded page when hits a timeout.

    :param url: The URL to retrieve.
    :param port: The port at which Chrome is running.
    :param timeout: The timeout after which page loading stops.
    :param isolate_tabs: If True, will isolate the new tab from other tabs. See the
      :py:func:`setup_browser` for more information.
    """
    page_state = PageState(url)

    try:
        browser, tab = setup_browser(port, timeout=_API_TIMEOUT, isolate_tabs=isolate_tabs)
    except Exception as e:
        _LOGGER.exception(e)
        return _get_error_result(url, e)

    try:
        _attach_listeners(tab, page_state)
        _perform_request(tab, timeout, page_state)
        if page_state.main_request_failed:
            raise Exception("Main request failed")
        _LOGGER.debug('requests_dict: %r', page_state.requests_dict.keys())
        return _gather_all_data(tab, page_state)
    except Exception as e:
        _LOGGER.exception(e)
        return _get_error_result(url, e)
    finally:
        _teardown_browser(browser, tab)


def _install(filename: str) -> None:
    """Install a specific Chrome binary by specifying its name.

    Only works for Debian-like systems.
    """
    import tempfile

    url = f's3://dbi2-ue2/google-chrome-stable/{filename}'
    with tempfile.TemporaryDirectory() as tmpdir:
        dest = os.path.join(tmpdir, filename)
        subprocess.check_call(['aws', 's3', 'cp', url, dest])
        subprocess.check_call(['sudo', 'dpkg', '-i', dest])


def _bisect():
    """Determine the most recent usable Chrome binary via a binary search.

    Useful when you suspect a Chrome release may be a broken or incompatible
    with DBI2 Gecko.
    """
    import re
    import subprocess

    url = 's3://dbi2-ue2/google-chrome-stable/'

    regex = re.compile(r'google-chrome-stable_(?P<version>\d+\.\d+\.\d+\.\d+)-1_amd64.deb')

    listing = subprocess.check_output(['aws', 's3', 'ls', url])
    versions = {}
    for line in listing.decode().split('\n'):
        match = regex.search(line)
        if match:
            versions[match.group('version')] = match.group(0)

    last_working_version = ''
    candidates = sorted(versions, key=lambda x: [int(y) for y in x.split('.')], reverse=True)
    while len(candidates) > 1:
        pivot_index = len(candidates) // 2
        filename = versions[candidates[pivot_index]]

        print(f'Next candidate: {filename} ({len(candidates)} versions left)')
        _install(filename)
        print(
            f'installed {filename}.  '
            'Now, manually test dbi2.gecko.chrome in a separate terminal window.',
        )

        good = False
        while True:
            print('Does dbi2.gecko.chrome appear to work now?  y/n ', end='')
            response = input().strip().lower()
            if response == 'y':
                last_working_version = candidates[pivot_index]
                good = True
                break
            elif response == 'n':
                good = False
                break

        if good:
            candidates = candidates[:pivot_index]
        else:
            candidates = candidates[pivot_index + 1:]

    print(f'last working version: {last_working_version}')


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('url', type=str, help='The URL to retrieve')
    parser.add_argument('--timeout', metavar='timeout', type=int,
                        help='timeout in seconds', default=_PAGE_TIMEOUT)
    parser.add_argument('--loglevel', default=logging.INFO)
    args = parser.parse_args()
    logging.basicConfig(level=args.loglevel)
    with optional_chrome_support(use_chrome=True, port=_DEFAULT_CHROME_PORT):
        result = retrieve(args.url, _DEFAULT_CHROME_PORT, args.timeout)
        sys.stdout.write(json.dumps(dataclasses.asdict(result)) + '\n')


if __name__ == '__main__':
    main()
