"""Verify: encrypt round-trip via items, same-operator invariance, fixed samples."""

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.deanonymize_engine import DeanonymizeEngine
from presidio_anonymizer.entities import (
    ConflictResolutionStrategy,
    OperatorConfig,
    RecognizerResult,
)

ENGINE = AnonymizerEngine()
KEY = "WmZq4t7w!z%C&F)J"

# 1. encrypt round-trip with a keep URL overlapping the encrypted email
text = "see https://example.com/u/john@example.com/x end"
email = (text.index("john@example.com"), text.index("john@example.com") + 16)
url = (text.index("https://"), text.index("/x end") + 2)
for strategy in (
    ConflictResolutionStrategy.MERGE_SIMILAR_OR_CONTAINED,
    ConflictResolutionStrategy.REMOVE_INTERSECTIONS,
):
    res = ENGINE.anonymize(
        text,
        [RecognizerResult("URL", url[0], url[1], 0.5),
         RecognizerResult("EMAIL_ADDRESS", email[0], email[1], 0.9)],
        {"URL": OperatorConfig("keep"),
         "EMAIL_ADDRESS": OperatorConfig("encrypt", {"key": KEY})},
        conflict_resolution=strategy,
    )
    assert "john@example.com" not in res.text, res.text
    dec = DeanonymizeEngine().deanonymize(
        res.text,
        res.items,
        {"EMAIL_ADDRESS": OperatorConfig("decrypt", {"key": KEY}),
         "URL": OperatorConfig("deanonymize_keep")},
    )
    assert dec.text == text, (strategy, dec.text, text)
    print(f"encrypt round-trip OK ({strategy.name})")

# 2. same-operator invariance: overlapping results, both redact
text2 = "aaaaaaaaaabbbbbcccccdddd"
for strategy in (
    ConflictResolutionStrategy.MERGE_SIMILAR_OR_CONTAINED,
    ConflictResolutionStrategy.REMOVE_INTERSECTIONS,
):
    res = ENGINE.anonymize(
        text2,
        [RecognizerResult("A", 0, 12, 0.9), RecognizerResult("B", 8, 20, 0.5)],
        {"DEFAULT": OperatorConfig("redact")},
        conflict_resolution=strategy,
    )
    print(f"all-redact {strategy.name}: {res.text!r}, items={[(i.entity_type, i.start, i.end) for i in res.items]}")

# 3. all-default-replace invariance (no operators dict at all)
res = ENGINE.anonymize(
    text2,
    [RecognizerResult("A", 0, 12, 0.9), RecognizerResult("B", 8, 20, 0.5)],
)
print("default replace:", repr(res.text), [(i.entity_type, i.operator) for i in res.items])

# 4. fixed audit sample: URL/date keep, SSN/email redact/mask/encrypt; no literal leaks
audit_text = "export at 2026-11-18: ssn 123-45-6789 email john.doe@example.com via https://example.com/u/john.doe@example.com"
spans = {
    "DATE_TIME": (audit_text.index("2026-11-18"), audit_text.index("2026-11-18") + 10),
    "SSN": (audit_text.index("123-45-6789"), audit_text.index("123-45-6789") + 11),
    "EMAIL_ADDRESS": (audit_text.index("john.doe@example.com"), audit_text.index("john.doe@example.com") + 20),
    "URL": (audit_text.index("https://"), len(audit_text)),
}
# the analyzer emits one result per occurrence: the email also appears inside the URL
second_email_start = audit_text.index("john.doe@example.com", spans["URL"][0])
results = [RecognizerResult(et, s, e, 0.8) for et, (s, e) in spans.items()]
results.append(RecognizerResult("EMAIL_ADDRESS", second_email_start, second_email_start + 20, 0.8))
operators = {
    "URL": OperatorConfig("keep"),
    "DATE_TIME": OperatorConfig("keep"),
    "SSN": OperatorConfig("redact"),
    "EMAIL_ADDRESS": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 100, "from_end": False}),
}
for strategy in (
    ConflictResolutionStrategy.MERGE_SIMILAR_OR_CONTAINED,
    ConflictResolutionStrategy.REMOVE_INTERSECTIONS,
):
    out = ENGINE.anonymize(audit_text, results, operators, conflict_resolution=strategy)
    print(f"\naudit {strategy.name}:\n  {out.text}")
    assert "123-45-6789" not in out.text
    assert "john.doe@example.com" not in out.text
    assert "2026-11-18" in out.text  # date keep still works outside conflicts
print("\nALL CHECKS PASSED")
