"""Tests for keep results conflicting with results using other operators.

A keep result must only leave characters in clear that no other result
covers. It must never win a conflict against a redacting operator, regardless
of scores, containment, overlap direction or conflict strategy.
"""

import pytest

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.deanonymize_engine import DeanonymizeEngine
from presidio_anonymizer.entities import (
    ConflictResolutionStrategy,
    OperatorConfig,
    RecognizerResult,
)

ALL_STRATEGIES = (
    ConflictResolutionStrategy.MERGE_SIMILAR_OR_CONTAINED,
    ConflictResolutionStrategy.REMOVE_INTERSECTIONS,
)

KEY = "WmZq4t7w!z%C&F)J"


def _operators(**entity_operators):
    operators = dict(entity_operators)
    operators.setdefault("DEFAULT", OperatorConfig("replace", {"new_value": "<X>"}))
    return operators


@pytest.mark.parametrize("strategy", ALL_STRATEGIES)
def test_keep_result_containing_another_entity_does_not_leave_it_in_clear(strategy):
    text = "x https://john@example.com y"
    email_start = text.index("john@example.com")
    results = [
        RecognizerResult("URL", 2, len(text) - 2, 0.5),
        RecognizerResult("EMAIL_ADDRESS", email_start, email_start + 16, 0.9),
    ]

    result = AnonymizerEngine().anonymize(
        text,
        results,
        _operators(
            URL=OperatorConfig("keep"),
            EMAIL_ADDRESS=OperatorConfig("redact"),
        ),
        conflict_resolution=strategy,
    )

    assert "john@example.com" not in result.text
    assert result.text == "x https:// y"
    assert [item.entity_type for item in result.items] == ["EMAIL_ADDRESS", "URL"]
    keep_item = next(item for item in result.items if item.entity_type == "URL")
    assert keep_item.operator == "keep"
    assert keep_item.text == "https://"


@pytest.mark.parametrize("strategy", ALL_STRATEGIES)
def test_partial_overlap_in_both_directions_keeps_no_covered_characters(strategy):
    text = "contact https://example.com/user/john@example.com now"
    url_start, url_end = 8, 47
    email_start = text.index("john@example.com")
    results = [
        RecognizerResult("URL", url_start, url_end, 0.5),
        RecognizerResult("EMAIL_ADDRESS", email_start, email_start + 16, 0.9),
    ]

    result = AnonymizerEngine().anonymize(
        text,
        results,
        _operators(
            URL=OperatorConfig("keep"),
            EMAIL_ADDRESS=OperatorConfig(
                "mask", {"masking_char": "*", "chars_to_mask": 100, "from_end": False}
            ),
        ),
        conflict_resolution=strategy,
    )

    assert "john@example.com" not in result.text
    # The keep URL retains only the prefix that the email result does not cover.
    assert result.text == "contact https://example.com/user/**************** now"
    keep_item = next(item for item in result.items if item.entity_type == "URL")
    assert (keep_item.start, keep_item.end, keep_item.text) == (
        url_start,
        email_start,
        "https://example.com/user/",
    )


@pytest.mark.parametrize("strategy", ALL_STRATEGIES)
def test_keep_on_the_right_of_an_overlap_does_not_keep_covered_text(strategy):
    text = "email john@example.com/path tail"
    email_start, email_end = 6, 22
    url_start = text.index("example.com/path")
    results = [
        RecognizerResult("EMAIL_ADDRESS", email_start, email_end, 0.9),
        RecognizerResult("URL", url_start, url_start + len("example.com/path"), 0.5),
    ]

    result = AnonymizerEngine().anonymize(
        text,
        results,
        _operators(
            URL=OperatorConfig("keep"),
            EMAIL_ADDRESS=OperatorConfig("redact"),
        ),
        conflict_resolution=strategy,
    )

    assert "john@example.com" not in result.text
    assert result.text == "email /path tail"
    keep_item = next(item for item in result.items if item.entity_type == "URL")
    assert keep_item.text == "/path"


@pytest.mark.parametrize("strategy", ALL_STRATEGIES)
def test_equal_indices_equal_scores_keep_loses_to_redact_in_either_order(strategy):
    text = "abc 123-45-6789 def"
    for ordered_results in (
        [RecognizerResult("URL", 4, 15, 0.8), RecognizerResult("SSN", 4, 15, 0.8)],
        [RecognizerResult("SSN", 4, 15, 0.8), RecognizerResult("URL", 4, 15, 0.8)],
    ):
        result = AnonymizerEngine().anonymize(
            text,
            ordered_results,
            _operators(
                URL=OperatorConfig("keep"),
                SSN=OperatorConfig("redact"),
            ),
            conflict_resolution=strategy,
        )

        assert "123-45-6789" not in result.text
        assert result.text == "abc  def"
        assert [item.entity_type for item in result.items] == ["SSN"]
        assert result.items[0].operator == "redact"


@pytest.mark.parametrize("strategy", ALL_STRATEGIES)
def test_higher_scored_keep_still_cannot_keep_another_entity(strategy):
    text = "aaaaaaaaaabbbbbcccccdddd"
    results = [
        RecognizerResult("URL", 0, 12, 0.95),
        RecognizerResult("SSN", 8, 20, 0.5),
    ]

    result = AnonymizerEngine().anonymize(
        text,
        results,
        _operators(
            URL=OperatorConfig("keep"),
            SSN=OperatorConfig("redact"),
        ),
        conflict_resolution=strategy,
    )

    assert result.text == "aaaaaaaa" + "dddd"
    keep_item = next(item for item in result.items if item.entity_type == "URL")
    assert (keep_item.start, keep_item.end) == (0, 8)
    redact_item = next(item for item in result.items if item.entity_type == "SSN")
    assert redact_item.operator == "redact"


def test_keep_fragmented_on_both_sides_of_a_contained_entity():
    text = "https://john@example.com/path"
    email_start = text.index("john@example.com")
    results = [
        RecognizerResult("URL", 0, len(text), 0.5),
        RecognizerResult("EMAIL_ADDRESS", email_start, email_start + 16, 0.9),
    ]

    result = AnonymizerEngine().anonymize(
        text,
        results,
        _operators(
            URL=OperatorConfig("keep"),
            EMAIL_ADDRESS=OperatorConfig("redact"),
        ),
    )

    assert "john@example.com" not in result.text
    assert result.text == "https:///path"
    keep_texts = sorted(item.text for item in result.items if item.entity_type == "URL")
    assert keep_texts == ["/path", "https://"]


def test_all_keep_configuration_is_completely_unchanged():
    text = "abc 123-45-6789 def"
    results = [
        RecognizerResult("SSN", 4, 15, 0.8),
        RecognizerResult("URL", 4, 15, 0.8),
    ]

    result = AnonymizerEngine().anonymize(
        text, results, {"DEFAULT": OperatorConfig("keep")}
    )

    assert result.text == text
    assert len(result.items) == 1
    assert result.items[0].operator == "keep"
    assert result.items[0].text == "123-45-6789"


@pytest.mark.parametrize("strategy", ALL_STRATEGIES)
def test_default_keep_still_loses_to_an_entity_level_redact(strategy):
    text = "x https://john@example.com y"
    email_start = text.index("john@example.com")
    results = [
        RecognizerResult("URL", 2, len(text) - 2, 0.5),
        RecognizerResult("EMAIL_ADDRESS", email_start, email_start + 16, 0.9),
    ]

    result = AnonymizerEngine().anonymize(
        text,
        results,
        {
            "DEFAULT": OperatorConfig("keep"),
            "EMAIL_ADDRESS": OperatorConfig("redact"),
        },
        conflict_resolution=strategy,
    )

    assert "john@example.com" not in result.text
    assert result.text == "x https:// y"


def test_keep_result_fully_covered_by_other_results_disappears():
    text = "abcdefghij"
    results = [
        RecognizerResult("URL", 0, 10, 0.5),
        RecognizerResult("SSN", 0, 5, 0.8),
        RecognizerResult("EMAIL_ADDRESS", 5, 10, 0.8),
    ]

    result = AnonymizerEngine().anonymize(
        text,
        results,
        _operators(
            URL=OperatorConfig("keep"),
            SSN=OperatorConfig("redact"),
            EMAIL_ADDRESS=OperatorConfig("redact"),
        ),
    )

    assert result.text == ""
    assert [item.entity_type for item in result.items] == [
        "EMAIL_ADDRESS",
        "SSN",
    ]


def test_non_overlapping_keep_and_redact_keep_their_original_spans():
    text = "aaa bbb ccc"
    results = [
        RecognizerResult("URL", 0, 3, 0.5),
        RecognizerResult("SSN", 8, 11, 0.8),
    ]

    result = AnonymizerEngine().anonymize(
        text,
        results,
        _operators(
            URL=OperatorConfig("keep"),
            SSN=OperatorConfig("redact"),
        ),
    )

    assert result.text == "aaa bbb "
    assert [
        (item.entity_type, item.start, item.end, item.text) for item in result.items
    ] == [
        ("SSN", 8, 8, ""),
        ("URL", 0, 3, "aaa"),
    ]


@pytest.mark.parametrize("strategy", ALL_STRATEGIES)
def test_encrypt_overlapping_keep_round_trips_back_to_the_original(strategy):
    text = "see https://example.com/u/john@example.com/x end"
    email_start = text.index("john@example.com")
    url_start = text.index("https://")
    url_end = text.index("/x end") + 2
    results = [
        RecognizerResult("URL", url_start, url_end, 0.5),
        RecognizerResult("EMAIL_ADDRESS", email_start, email_start + 16, 0.9),
    ]

    anonymized = AnonymizerEngine().anonymize(
        text,
        results,
        _operators(
            URL=OperatorConfig("keep"),
            EMAIL_ADDRESS=OperatorConfig("encrypt", {"key": KEY}),
        ),
        conflict_resolution=strategy,
    )
    assert "john@example.com" not in anonymized.text

    deanonymized = DeanonymizeEngine().deanonymize(
        anonymized.text,
        anonymized.items,
        {
            "URL": OperatorConfig("deanonymize_keep"),
            "EMAIL_ADDRESS": OperatorConfig("decrypt", {"key": KEY}),
            "DEFAULT": OperatorConfig("decrypt", {"key": KEY}),
        },
    )

    assert deanonymized.text == text


def test_fixed_export_sample_has_no_ssn_or_email_literal_under_either_strategy():
    text = (
        "export at 2026-11-18: ssn 123-45-6789 email john.doe@example.com "
        "via https://example.com/u/john.doe@example.com"
    )
    date_span = (text.index("2026-11-18"), text.index("2026-11-18") + 10)
    ssn_span = (text.index("123-45-6789"), text.index("123-45-6789") + 11)
    first_email = text.index("john.doe@example.com")
    second_email = text.index("john.doe@example.com", first_email + 1)
    url_start = text.index("https://")
    results = [
        RecognizerResult("DATE_TIME", date_span[0], date_span[1], 0.8),
        RecognizerResult("SSN", ssn_span[0], ssn_span[1], 0.8),
        RecognizerResult("EMAIL_ADDRESS", first_email, first_email + 20, 0.8),
        RecognizerResult("EMAIL_ADDRESS", second_email, second_email + 20, 0.8),
        RecognizerResult("URL", url_start, len(text), 0.8),
    ]
    operators = _operators(
        URL=OperatorConfig("keep"),
        DATE_TIME=OperatorConfig("keep"),
        SSN=OperatorConfig("redact"),
        EMAIL_ADDRESS=OperatorConfig(
            "mask", {"masking_char": "*", "chars_to_mask": 100, "from_end": False}
        ),
    )

    for strategy in ALL_STRATEGIES:
        result = AnonymizerEngine().anonymize(
            text, results, operators, conflict_resolution=strategy
        )

        assert "123-45-6789" not in result.text
        assert "john.doe@example.com" not in result.text
        # Keep still works for results that do not conflict.
        assert "2026-11-18" in result.text
        assert "https://example.com/u/" in result.text
