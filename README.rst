How to Add New Fingerprints
===========================

This guide briefly describes what fingerprints are, how they work, and shows you how to add new ones.

Installation
------------

    pip install requirements.txt

Scripts
-------

- extract.py: extracts fingerprints and print them to standard output
- fingerprints.py: the collection of fingerprint definitions
- howto-fp.rst: fingerprinting manual
- requirements.txt: required packages
- retrieve.py: retrieve a URL and save the results to a JSON file
- webkit.py: wrapper around QtWebkit

Usage
-----

To fetch a page and run it through the fingerprint extractor::

    (fp)bash-3.2$ python retrieve.py http://profound.net | python extract.py -
    {"category": "web_technology_tools", "name": "jQuery"}

What are Fingerprints?
----------------------

A Fingerprint is indicates the presence of a certain Web technology on a domain.
Fingerprints are classified by their category and name.
Currently, we have the following categories:

- advertising
- cms
- ecommerce
- social_networks
- web_analytics
- web_technology_tools

How do Fingerprints Work?
-------------------------

From a software development point of view, a fingerprint is a callback function.
When our software processes a Web page, it invokes all the fingerprint callbacks, one by one.
When a callback returns True, it indicates the presence of the fingerprint on the page.

The register_fingerprint decorator indicates the fingerprint's category and name, and registers it in the list of callbacks.

The callback receives the following arguments:

- page: The full HTML of the Web page, as a string.
- tree: The XML tree parsed from the Web page.
- headers: HTTP headers collected while retrieving the page, as a dictionary keyed by the header name.
- nreq: A callback that accepts a single string argument.

The XML tree is parsed using `lxml <http://lxml.de/>`_.
More specifically, this is the root node returned by the `lxml.html.document_fromstring <http://lxml.de/lxmlhtml.html#parsing-html>`_ function.

nreq is a legacy callback that accepts a single argument and checks for its presence in the network replies for the page.

The fingerprint may use any combination of the above four arguments to determine whether to return True or False.

Examples
^^^^^^^^

For example, this callback just checks for the presence of a string in HTML:

.. code-block:: python

    @register_fingerprint('ecommerce', 'corecommerce.com')
    def eCommerce_corecommerce_com(page, tree, headers, nreq):
        return "Powered By: CoreCommerce" in page

This callback leverages the XML tree to check the presence of a specific element:

.. code-block:: python

    @register_fingerprint('advertising', 'Yext')
    def advertising_Yext(page, tree, headers, nreq):
        return bool(tree.xpath(r"""//script[contains(@src,".yext.com/")]"""))

This callback checks the headers:

.. code-block:: python

    @register_fingerprint('web_technology_tools', 'P3P Policy')
    def WebTechTools_P3PPolicy(page, tree, headers, nreq):
        return headers.get("P3P")

Finally, this callback leverages nreq:

.. code-block:: python

    @register_fingerprint('cms', 'Ceros')
    def CMS_Ceros(page, tree, headers, nreq):
        return nreq(".ceros.com/") or bool(tree.xpath(r"""//a[contains(@href,"//view.ceros.com/")]"""))

How do I Add a New Fingerprint?
-------------------------------

To start, you need:

- An appropriate category and name for your new fingerprint
- Some example Web pages that have the fingerprint

Start by examining the HTML of your example Web pages.
Look for common characteristics and determine the fingerprint implementation details.
Implement the fingerprint as a callback in fingerprints.py:

.. code-block:: python

    @register_fingerprint('{category}', '{name}')
    def CMS_Ceros(page, tree, headers, nreq):
        return False  # The implementation goes here

If you omit the decorator, our software will not detect your new fingerprint.
