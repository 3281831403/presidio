"""Scenarios whose output and items must be identical before/after the fix."""

import json

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import (
    ConflictResolutionStrategy,
    OperatorConfig,
    RecognizerResult,
)

ENGINE = AnonymizerEngine()
CASES = []

text = "aaaaaaaaaabbbbbcccccdddd"
results = [RecognizerResult("A", 0, 12, 0.9), RecognizerResult("B", 8, 20, 0.5)]
for strategy in (
    ConflictResolutionStrategy.MERGE_SIMILAR_OR_CONTAINED,
    ConflictResolutionStrategy.REMOVE_INTERSECTIONS,
):
    CASES.append(("all-redact overlap", text, results, {"DEFAULT": OperatorConfig("redact")}, strategy))
    CASES.append(("all-replace overlap", text, results, None, strategy))
    CASES.append(("same-op mask overlap", text, results, {"DEFAULT": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 5, "from_end": False})}, strategy))
    CASES.append(("all-keep overlap", text, results, {"DEFAULT": OperatorConfig("keep")}, strategy))

# same entity-type merge chain (existing test case)
t2 = "aaaaaaaaaaaa tail"
r2 = [RecognizerResult("PERSON", 5, 9, 0.4), RecognizerResult("PERSON", 0, 6, 0.9), RecognizerResult("PERSON", 8, 12, 0.5)]
CASES.append(("same-type chain", t2, r2, None, ConflictResolutionStrategy.MERGE_SIMILAR_OR_CONTAINED))

# contained + equal indices existing cases
t3 = "aaaaaaaaaa"
CASES.append(("contained", t3, [RecognizerResult("LOCATION", 2, 5, 0.9), RecognizerResult("PERSON", 0, 10, 0.3)], None, ConflictResolutionStrategy.MERGE_SIMILAR_OR_CONTAINED))
t4 = "aaaaa"
CASES.append(("equal indices", t4, [RecognizerResult("PERSON", 0, 5, 0.9), RecognizerResult("LOCATION", 0, 5, 0.4)], None, ConflictResolutionStrategy.MERGE_SIMILAR_OR_CONTAINED))

for name, t, rs, ops, strategy in CASES:
    out = ENGINE.anonymize(t, [RecognizerResult(r.entity_type, r.start, r.end, r.score) for r in rs], ops, conflict_resolution=strategy)
    print(json.dumps({"case": name, "strategy": strategy.name if strategy else None,
                      "text": out.text,
                      "items": [(i.entity_type, i.start, i.end, i.operator, i.text) for i in out.items]}))
