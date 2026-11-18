"""More leak directions: keep-on-right overlap, tie with keep last, all-keep baseline."""

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import (
    ConflictResolutionStrategy,
    OperatorConfig,
    RecognizerResult,
)

ENGINE = AnonymizerEngine()
OPERATORS = {
    "URL": OperatorConfig("keep"),
    "EMAIL_ADDRESS": OperatorConfig("redact"),
    "SSN": OperatorConfig("redact"),
    "DEFAULT": OperatorConfig("replace", {"new_value": "<X>"}),
}

def show(title, text, results):
    print(f"\n--- {title} ---")
    for strategy in (
        ConflictResolutionStrategy.MERGE_SIMILAR_OR_CONTAINED,
        ConflictResolutionStrategy.REMOVE_INTERSECTIONS,
    ):
        out = ENGINE.anonymize(text, list(results), OPERATORS, conflict_resolution=strategy)
        print(f"{strategy.name:30s} -> {out.text!r}")
        print(f"{'':30s}    items={[(i.entity_type, i.operator, i.start, i.end) for i in out.items]}")

# D: keep on the right of the non-keep entity, partial overlap
text = "email john@example.com/path tail"
email = (6, 22)   # john@example.com
url = (18, 33)    # .com/path tail? make a URL span starting inside email
url = (text.index("example.com/path"), text.index("example.com/path") + len("example.com/path"))
show("keep URL right of redact EMAIL (partial overlap)", text,
     [RecognizerResult("EMAIL_ADDRESS", email[0], email[1], 0.9),
      RecognizerResult("URL", url[0], url[1], 0.5)])

# E: equal indices, equal score, keep listed LAST -> today last wins
text3 = "abc 123-45-6789 def"
show("equal indices equal scores, keep LAST", text3,
     [RecognizerResult("SSN", 4, 15, 0.8),
      RecognizerResult("URL", 4, 15, 0.8)])

# C: REMOVE_INTERSECTIONS, keep has HIGHER score, keep left
text4 = "aaaaaaaaaabbbbbcccccdddd"
show("keep higher score, left, partial overlap", text4,
     [RecognizerResult("URL", 0, 12, 0.95),
      RecognizerResult("SSN", 8, 20, 0.5)])

# baseline: all keep (DEFAULT=keep), behavior must stay identical
out = ENGINE.anonymize(
    "abc 123-45-6789 def",
    [RecognizerResult("SSN", 4, 15, 0.8), RecognizerResult("URL", 4, 15, 0.8)],
    {"DEFAULT": OperatorConfig("keep")},
)
print("\nall-keep baseline:", repr(out.text), [(i.entity_type, i.operator, i.start, i.end) for i in out.items])
