"""Extract fingerprints from the specified JSON file."""
import argparse
import json
import logging
import re
import sys

import selectolax.lexbor
import selectolax.parser

import fingerprints

_LOGGER = logging.getLogger(__name__)
_LOGGER.addHandler(logging.NullHandler())


HTML_ENCODING_REGEX = re.compile(r"""
        \ ?
        (
            encoding=
            ["'](?P<encoding>[-\w\d]+)["']
            |
            charset=["'](?P<quoted_charset>[-\w\d]+)["']
            |
            charset=(?P<unquoted_charset>[-\w\d]+)
        )
        """, re.VERBOSE)
"""Detects XML encoding declarations. Encoding appears in tags like::

    <?xml version="1.0" encoding="UTF-8"?>

Charset appears in tags like::

    <meta http-equiv='content-type' content='text/html; charset=utf-8' />"""


def _strip_xml_encoding(html: str) -> str:
    """lxml won't parse Unicode strings that contain encoding information.
    This function strips that encoding information so that the string can be
    parsed with lxml."""
    return HTML_ENCODING_REGEX.sub("", html)


def parse_html(html_string):
    """Parse a HTML string.

    Returns:
        A tree or None if parsing failed."""
    html_string = _strip_xml_encoding(html_string)
    parser = selectolax.lexbor.LexborHTMLParser
    # parser = selectolax.parser.HTMLParser
    return parser(html_string)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('inputfile')
    args = parser.parse_args()

    if args.inputfile == '-':
        fetched = json.load(sys.stdin)
    else:
        with open(args.inputfile) as fin:
            fetched = json.load(fin)

    def has_fragment(url_fragment):
        for req in fetched['all_net_reply']:
            if url_fragment in req:
                return True
        return False

    tree = parse_html(fetched['html'])
    if tree is None:
        sys.stderr.write('failed to retrieve or parse the page\n')
        return

    for fp in fingerprints.ALL_FINGERPRINTS:
        if fp(fetched['html'], tree, fetched['headers'], has_fragment):
            d = {'category': fp.category, 'name': fp.name}
            sys.stdout.write(json.dumps(d) + '\n')


if __name__ == '__main__':
    main()
