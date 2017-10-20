#!/usr/bin/env python
#
# (C) Copyright: Profound Networks, LLC 2016
#
from __future__ import print_function
import sys
import argparse
import logging
import json

from PySide.QtGui import QApplication

import webkit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--loglevel", type=str, default=logging.ERROR)
    parser.add_argument("--timeout", type=int, default=webkit.DEFAULT_TIMEOUT)
    args = parser.parse_args()

    logging.basicConfig(level=args.loglevel)

    app = QApplication(__file__)

    url = args.url if args.url.startswith("http") else "http://" + args.url
    result = webkit.load_url(url, timeout=args.timeout)

    dict_ = dict(result._asdict())
    dict_["network_error"] = str(dict_["network_error"])
    print(json.dumps(dict_))

    del app
    return 0


if __name__ == "__main__":
    sys.exit(main())
