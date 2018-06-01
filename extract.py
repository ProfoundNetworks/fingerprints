"""Extract fingerprints from the specified JSON file."""
from __future__ import print_function

import argparse
import json
import logging
import sys

import lxml.etree
import lxml.html

import fingerprints

_LOGGER = logging.getLogger(__name__)
_LOGGER.addHandler(logging.NullHandler())


def parse_html(html_string):
    """Parse a HTML string.

    Returns:
        A tree or None if parsing failed."""
    # html_string = pntools.misc.strip_xml_encoding(html_string)
    try:
        return lxml.html.document_fromstring(html_string)
    except (lxml.etree.ParserError, UnicodeError, ValueError) as ex:
        _LOGGER.warning("Unable to parse HTML from string: %r", ex)
        return None


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
            sys.stdout.write(json.dumps({'category': fp.category, 'name': fp.name}) + '\n')


if __name__ == '__main__':
    main()
