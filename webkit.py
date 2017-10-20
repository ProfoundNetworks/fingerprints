"""Download and render pages using QT's WebKit."""
import re
import collections
import logging
import time

import six

import PySide.QtCore
import PySide.QtWebKit
import PySide.QtNetwork

from PySide.QtGui import QApplication
from PySide.QtWebKit import QWebSettings

logger = logging.getLogger(__name__)

_RESULT_FIELDS = [
    "network_error", "url", "redirected_url", "headers", "html", "all_net_reply",
    "ip_address", "cookies", "page_plus_frames", "auth_request", "error_403",
    "tld", 'timer'
]
_TIMEOUT_ERROR = PySide.QtNetwork.QNetworkReply.NetworkError.TimeoutError
_RE_NOSCRIPT = re.compile("(?is)< *noscript *>.+?< */noscript *>")

Result = collections.namedtuple("Result", _RESULT_FIELDS)


def create_result(**kwargs):
    """Create a Result instance.

    Missing fields will be set to None."""
    fields = {x: None for x in _RESULT_FIELDS}
    fields.update(kwargs)
    return Result(**fields)


def _unescape_html(m):
    def fixup(m):
        text = m.group(0)

        try:
            text = six.unichr(six.moves.html_entities.name2codepoint[text[1:-1]])
        except KeyError:
            pass
        return text  # leave as is
    return re.sub("&\w+;", fixup, m.group(0))


def _fix_noscript(page):
    """restore the content inside <noscript> after Webkit has changed it
    (from "<" to "&lt;", from "&" to "&amp;" etc.)"""
    return _RE_NOSCRIPT.sub(_unescape_html, page)


#
# the default user agent includes the string "Safari" which makes some sites
# serve mobile content.
#
USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.34 \
(KHTML, like Gecko) Qt/4.8.2'

DEFAULT_TIMEOUT = 20


def _dbi1_get_tld(redirected_url):
    #                 tld part (port | path | end of line)
    # this is copied directly from the DBI1 version. There are
    # better ways.
    m = re.search(r"""([^.:/]+)(:[0-9]+|/|$)""", redirected_url)
    tld = m.group(1) if m else ""
    return tld


def _get_page_plus_frames(main_frame):
    nodes = [main_frame]
    page_plus_frames = []
    while nodes:
        frame = nodes.pop(0)
        nodes = frame.childFrames() + nodes
        page_plus_frames.append(frame.toHtml())
    return page_plus_frames


def _dbi1_defragment(qt_url):
    #
    # DBI1 defragments the URL, so we do too.
    #
    return unicode(qt_url.toString(PySide.QtCore.QUrl.FormattingOption.RemoveFragment))


def decode(qbytearray):
    """Convert a QByteArray to a Unicode string.

    If this contains broken Unicode, then downstream applications (e.g. DBI2)
    will fail when trying to decode it.  Deal with that here instead."""
    return str(qbytearray).decode('utf-8', errors='replace')


class Page(PySide.QtWebKit.QWebPage):
    """Loads a page from a URL and renders it using WebKit."""

    def __init__(self, user_agent=USER_AGENT):
        if QApplication.instance() is None:
            raise RuntimeError('QApplication is not instantiated yet.')
        super(Page, self).__init__()
        self.user_agent = user_agent
        self.cookie_jar = PySide.QtNetwork.QNetworkCookieJar()
        self.auth_request = []
        self.set_attributes()

    def set_attributes(self):
        """Override this method to specify your own settings."""
        s = self.settings()
        s.setAttribute(QWebSettings.AutoLoadImages, False)
        s.setAttribute(QWebSettings.JavascriptEnabled, True)
        s.setAttribute(QWebSettings.JavaEnabled, False)
        s.setAttribute(QWebSettings.PluginsEnabled, False)
        s.setAttribute(QWebSettings.PrivateBrowsingEnabled, True)
        s.setAttribute(QWebSettings.JavascriptCanOpenWindows, False)
        s.setAttribute(QWebSettings.JavascriptCanAccessClipboard, False)
        s.setAttribute(QWebSettings.DeveloperExtrasEnabled, False)
        s.setAttribute(QWebSettings.LocalContentCanAccessRemoteUrls, False)
        s.setAttribute(QWebSettings.LocalContentCanAccessFileUrls, False)
        s.setAttribute(QWebSettings.XSSAuditingEnabled, False)

    def javaScriptAlert(self, frame, msg):
        logger.debug("javaScriptAlert called")

    def javaScriptConfirm(self, frame, msg):
        logger.debug("javaScriptConfirm called")
        return True

    def javaScriptPrompt(self, frame, msg, default_value):
        logger.debug("javaScriptPrompt called")

    def shouldInterruptJavaScript(self):
        logger.debug("shouldInterruptJavaScript called")
        return True

    def userAgentForUrl(self, url):
        return self.user_agent

    def _on_net_reply(self, net_reply):
        key = _dbi1_defragment(net_reply.url())
        logger.debug("_on_net_reply: key: %s", key)
        if not self.last_error and net_reply.error() and \
                net_reply.attribute(net_reply.request().HttpStatusCodeAttribute) == 403:
            self.error_403 = True
        self.all_net_reply[key] = {decode(k): decode(v) for (k, v) in net_reply.rawHeaderPairs()}
        self.last_error = self.errors[key] = net_reply.error()
        if bool(self.last_error):
            logging.debug("errors[%r] = %r", key, self.errors[key])

    def _authenticate(self, mix, authenticator):
        self.auth_request = [type(mix).__name__, authenticator.realm()]

    def _sslErrors(self, net_reply, err_list):
        net_reply.ignoreSslErrors()

    def load_url(self, url, timeout=DEFAULT_TIMEOUT):
        """Load the specified URL and render it.  Returns a Result instance."""
        meth_name = "load_url"
        time_started = time.time()
        self.last_error = PySide.QtNetwork.QNetworkReply.NetworkError.NoError
        loop = PySide.QtCore.QEventLoop()
        timer = PySide.QtCore.QTimer()
        timer.setSingleShot(True)
        timer.timeout.connect(loop.quit)
        self.mainFrame().loadFinished.connect(loop.quit)

        self.all_net_reply = {}
        self.errors = {}
        self.error_403 = False
        self.networkAccessManager().finished.connect(self._on_net_reply)
        self.networkAccessManager().setCookieJar(self.cookie_jar)
        self.networkAccessManager().authenticationRequired.connect(self._authenticate)
        self.networkAccessManager().proxyAuthenticationRequired.connect(self._authenticate)
        self.networkAccessManager().sslErrors.connect(self._sslErrors)

        logger.debug("%s: loading %s", meth_name, url)

        self.mainFrame().load(PySide.QtCore.QUrl(url))
        timer.start(timeout * 1000)

        logger.debug("%s: waiting for timeout (%s)", meth_name, timeout)
        loop.exec_()

        logger.debug("%s: download is finished", meth_name)
        if timer.isActive():
            logger.debug("%s: timer is still running", meth_name)
            timer.stop()
            redirected_url = _dbi1_defragment(self.mainFrame().url())

            logger.debug("%s: redirected_url: %r", meth_name, redirected_url)

            if redirected_url in self.all_net_reply:
                headers = self.all_net_reply[redirected_url]

                adrs = PySide.QtNetwork.QHostInfo.fromName(
                    self.mainFrame().url().host()
                ).addresses()
                ip_address = adrs[0].toString() if len(adrs) else None

                cookies = []
                for cookie in self.cookie_jar.allCookies():
                    #
                    # .domain() returns a QString
                    # .name() returns a QByteArray
                    #
                    cookies.append((unicode(cookie.domain()), decode(cookie.name())))

                #
                # QString -> UTF-8 -> file
                #
                # We expect that WebKit determined the correct page encoding
                # for us.
                #
                html = _fix_noscript(self.mainFrame().toHtml())
                return Result(
                    self.errors[redirected_url], url, redirected_url,
                    headers, html, self.all_net_reply, ip_address, cookies,
                    _get_page_plus_frames(self.mainFrame()), self.auth_request,
                    self.error_403, _dbi1_get_tld(redirected_url),
                    time.time() - time_started
                )
            else:
                logger.debug("%s: encountered last_error: %r", meth_name,
                             self.last_error)
                return create_result(network_error=self.last_error, url=url,
                                     redirected_url=redirected_url,
                                     timer=time.time() - time_started)
        else:
            logger.debug("%s: timeout", meth_name)
            return create_result(network_error=_TIMEOUT_ERROR, url=url,
                                 timer=time.time() - time_started)


def load_url(url, *args, **kwargs):
    return Page().load_url(url, *args, **kwargs)


def supress_qtdebug(fin):
    """Supress all lines that contain QT debug statements.

    This stuff usually goes on stderr, which we ignore.
    Unfortunately, on some platforms, it ends up in stdout, together with
    the actual output we need."""
    debug_lines = [
        "QFont::setPixelSize: Pixel size <= 0 (0)\n",
        "QNetworkReplyImplPrivate::error: Internal problem, this method must \
only be called once.\n",
        "content-type missing in HTTP POST, defaulting to \
application/x-www-form-urlencoded. Use QNetworkRequest::setHeader() \
to fix this problem.\n",
        "Home directory not accessible: Permission denied\n",
    ]
    debug_regex = re.compile(
        r"load glyph failed err=\d+ face=0x[0-9a-f]+, glyph=\d"
    )
    for line in fin:
        if line not in debug_lines and debug_regex.match(line) is None:
            yield line
