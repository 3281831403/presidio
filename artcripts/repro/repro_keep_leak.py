"""Reproduce keep-vs-other-operator conflict leaks (read-only probe)."""

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import (
    ConflictResolutionStrategy,
    OperatorConfig,
    RecognizerResult,
)

ENGINE = AnonymizerEngine()

# URL/keep vs EMAIL/mask, partial overlap (email embedded inside URL)
TEXT = "contact https://example.com/user/john@example.com now"
# find spans
url_span = (8, 47)
email_span = (TEXT.index("john@example.com"), TEXT.index("john@example.com") + len("john@example.com"))
print("text:", TEXT)
print("url span:", url_span, TEXT[url_span[0]:url_span[1]])
print("email span:", email_span, TEXT[email_span[0]:email_span[1]])

OPERATORS = {
    "URL": OperatorConfig("keep"),
    "EMAIL_ADDRESS": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 100, "from_end": False}),
    "SSN": OperatorConfig("redact"),
    "DEFAULT": OperatorConfig("replace", {"new_value": "<X>"}),
}

for strategy in (
    ConflictResolutionStrategy.MERGE_SIMILAR_OR_CONTAINED,
    ConflictResolutionStrategy.REMOVE_INTERSECTIONS,
):
    results = [
        RecognizerResult("URL", url_span[0], url_span[1], 0.5),
        RecognizerResult("EMAIL_ADDRESS", email_span[0], email_span[1], 0.9),
    ]
    out = ENGINE.anonymize(TEXT, results, OPERATORS, conflict_resolution=strategy)
    print(f"\n== {strategy.name} ==")
    print("out text:", out.text)
    print("items:", [(i.entity_type, i.start, i.end, i.operator, i.text) for i in out.items])
    print("LEAK email literal present:", "john@example.com" in out.text)

# containment: URL keep fully contains EMAIL mask, keep lower score
TEXT2 = "x https://john@example.com y"
url2 = (2, len(TEXT2) - 2)
email2 = (TEXT2.index("john@example.com"), TEXT2.index("john@example.com") + 16)
print("\n\n--- containment, keep(URL) contains mask(EMAIL) ---")
print("text:", TEXT2, url2, email2)
for strategy in (
    ConflictResolutionStrategy.MERGE_SIMILAR_OR_CONTAINED,
    ConflictResolutionStrategy.REMOVE_INTERSECTIONS,
):
    results = [
        RecognizerResult("URL", url2[0], url2[1], 0.5),
        RecognizerResult("EMAIL_ADDRESS", email2[0], email2[1], 0.9),
    ]
    out = ENGINE.anonymize(TEXT2, results, OPERATORS, conflict_resolution=strategy)
    print(f"== {strategy.name}: {out.text!r}")
    print("   items:", [(i.entity_type, i.operator, i.text) for i in out.items])
    print("   LEAK:", "john@example.com" in out.text)

# equal indices, equal scores: keep first vs redact second
TEXT3 = "abc 123-45-6789 def"
ssn3 = (4, 15)
url3 = (4, 15)
print("\n--- equal indices equal scores: keep(URL) vs redact(SSN) ---")
for strategy in (
    ConflictResolutionStrategy.MERGE_SIMILAR_OR_CONTAINED,
    ConflictResolutionStrategy.REMOVE_INTERSECTIONS,
):
    results = [
        RecognizerResult("URL", url3[0], url3[1], 0.8),
        RecognizerResult("SSN", ssn3[0], ssn3[1], 0.8),
    ]
    out = ENGINE.anonymize(TEXT3, results, OPERATORS, conflict_resolution=strategy)
    print(f"== {strategy.name}: {out.text!r}")
    print("   items:", [(i.entity_type, i.operator) for i in out.items])
    print("   LEAK:", "123-45-6789" in out.text)
