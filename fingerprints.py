#
# (C) Copyright: Profound Networks, LLC 2017
#
# flake8: noqa
"""Implements functionality for extracting fingerprints from HTML."""

CATEGORIES = (
    'advertising',
    'cms',
    'ecommerce',
    'social_networks',
    'web_analytics',
    'web_technology_tools',
)
"""A list of allowed fingerprint categories."""

ALL_FINGERPRINTS = []
"""A list of all fingerprint function objects."""

FINGERPRINTS = {category: [] for category in CATEGORIES}
"""Lists of fingerprint function objects, keyed by category."""


class register_fingerprint(object):
    """A decorator that registers a fingerprint in FINGERPRINTS and ALL_FINGERPRINTS
    global variables. Expects two arguments: category and name which are then
    assigned as function properties."""

    def __init__(self, category, name):
        self.category = category
        self.name = name

    def __call__(self, original_func):
        if self.category not in CATEGORIES:
            raise ValueError('Category %s is not allowed.' % self.category)
        FINGERPRINTS[self.category].append(original_func)
        ALL_FINGERPRINTS.append(original_func)
        original_func.category = self.category
        original_func.name = self.name

        def wrappee(*args, **kwargs):
            return original_func(*args, **kwargs)
        return wrappee


#
# The code above is just plumbing: you don't need to touch or understand it.
# Add your fingerprints below.
#


@register_fingerprint('web_technology_tools', 'IFrame')
def WebTechTools_IFrame(page, tree, headers, nreq):
    return bool(tree.css_matches(r"""iframe"""))


@register_fingerprint('web_technology_tools', 'jQuery')
def WebTechTools_jQuery(page, tree, headers, nreq):
    return tree.script_srcs_contain(("/jquery.js",))
