"""Heuristic phishing-detection engine.

Independent Python implementation of the same detection engine published to
npm as ``@farksecurity/phish-signals`` (``../../typescript``). Not a binding
around it — see ``../../conformance/`` for what keeps the two in agreement on
what a given input means.

Nothing is ported yet. Once modules land, this file's role is the same as
``typescript/src/index.ts``: the public API surface. Everything a consumer
needs is re-exported from here; the individual submodules underneath are
internal layout, not a contract. Mirror index.ts's re-export list and
grouping (shared types; domain/punycode helpers; input handling; checks;
scoring/aggregation/output; parsing) as each piece is ported, e.g.::

    from .domains import registrable_domain, normalize_confusables, brand_label
    from .signals import score_signals, assess_confidence

    __all__ = ["registrable_domain", "normalize_confusables", "brand_label", ...]
"""

__version__ = "0.1.0"
