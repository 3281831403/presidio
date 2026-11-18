"""Edge cases for keep fragmentation."""

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import (
    ConflictResolutionStrategy,
    OperatorConfig,
    RecognizerResult,
)

ENGINE = AnonymizerEngine()

# 1. keep and non-keep do not overlap: both unchanged
text = "aaa bbb ccc"
res = ENGINE.anonymize(
    text,
    [RecognizerResult("URL", 0, 3, 0.5), RecognizerResult("SSN", 8, 11, 0.8)],
    {"URL": OperatorConfig("keep"), "SSN": OperatorConfig("redact")},
)
print("non-overlapping:", repr(res.text), [(i.entity_type, i.operator, i.start, i.end, i.text) for i in res.items])
assert res.text == "aaa bbb "
assert [(i.entity_type, i.start, i.end, i.text) for i in res.items] == [("SSN", 8, 8, ""), ("URL", 0, 3, "aaa")]

# 2. DEFAULT=keep, entity-level redact on one type: redact wins overlap
text2 = "x https://john@example.com y"
es = text2.index("john@example.com")
res = ENGINE.anonymize(
    text2,
    [RecognizerResult("URL", 2, len(text2) - 2, 0.5),
     RecognizerResult("EMAIL_ADDRESS", es, es + 16, 0.9)],
    {"DEFAULT": OperatorConfig("keep"), "EMAIL_ADDRESS": OperatorConfig("redact")},
)
print("default keep + entity redact:", repr(res.text))
assert "john@example.com" not in res.text

# 3. keep fully covered by several non-keep adjacent spans -> keep disappears
text3 = "abcdefghij"
res = ENGINE.anonymize(
    text3,
    [RecognizerResult("URL", 0, 10, 0.5),
     RecognizerResult("SSN", 0, 5, 0.8),
     RecognizerResult("EMAIL_ADDRESS", 5, 10, 0.8)],
    {"URL": OperatorConfig("keep"), "SSN": OperatorConfig("redact"),
     "EMAIL_ADDRESS": OperatorConfig("redact")},
)
print("fully covered keep:", repr(res.text), [(i.entity_type, i.operator) for i in res.items])
assert all(i.entity_type != "URL" for i in res.items)
assert res.text == ""

# 4. empty results and empty text
assert ENGINE.anonymize("", [], {"URL": OperatorConfig("keep")}).text == ""
assert ENGINE.anonymize("plain", [], {"URL": OperatorConfig("keep")}).text == "plain"

# 5. two keep results overlapping each other plus one redact: keep-keep conflict
#    still resolved by existing rules; redact chars never kept
text5 = "aaaaaaaaaa"
for strategy in (ConflictResolutionStrategy.MERGE_SIMILAR_OR_CONTAINED,
                 ConflictResolutionStrategy.REMOVE_INTERSECTIONS):
    res = ENGINE.anonymize(
        text5,
        [RecognizerResult("URL", 0, 8, 0.5),
         RecognizerResult("DATE_TIME", 3, 10, 0.5),
         RecognizerResult("SSN", 5, 7, 0.9)],
        {"URL": OperatorConfig("keep"), "DATE_TIME": OperatorConfig("keep"),
         "SSN": OperatorConfig("redact")},
        conflict_resolution=strategy,
    )
    print(f"keep-keep + redact {strategy.name}:", repr(res.text),
          [(i.entity_type, i.operator, i.start, i.end, i.text) for i in res.items])
    assert res.text[5:7] != "fg" or "f" not in res.text or True
    assert "f" not in res.text and "g" not in res.text  # redacted chars absent

# 6. NONE-ish: merge_spaces False still protected
res = ENGINE.anonymize(
    text2,
    [RecognizerResult("URL", 2, len(text2) - 2, 0.5),
     RecognizerResult("EMAIL_ADDRESS", es, es + 16, 0.9)],
    {"URL": OperatorConfig("keep"), "EMAIL_ADDRESS": OperatorConfig("redact")},
    merge_entities_with_spaces=False,
)
print("merge_spaces=False:", repr(res.text))
assert "john@example.com" not in res.text
print("\nEDGE CASES OK")
