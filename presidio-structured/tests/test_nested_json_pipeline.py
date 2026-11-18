"""End-to-end tests for arbitrarily nested JSON (objects, arrays, scalars)."""

import copy

from presidio_analyzer import BatchAnalyzerEngine
from presidio_anonymizer import BatchAnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from presidio_structured import JsonAnalysisBuilder, StructuredEngine
from presidio_structured.config import StructuredAnalysis
from presidio_structured.data.data_processors import JsonDataProcessor


def _json_type_shape(value):
    """Return the JSON type/structure of a value without comparing contents."""
    if isinstance(value, dict):
        return {key: _json_type_shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_type_shape(item) for item in value]
    return type(value)


def test_generate_analysis_finds_fields_inside_object_arrays(customer_export):
    analysis = JsonAnalysisBuilder().generate_analysis(customer_export)

    mapping = analysis.entity_mapping
    assert mapping["records.name"] == "PERSON"
    assert mapping["records.ssn"] == "US_SSN"
    assert mapping["records.email"] == "EMAIL_ADDRESS"
    assert mapping["records.phone"] == "PHONE_NUMBER"
    assert mapping["records.manager.name"] == "PERSON"
    assert mapping["records.manager.email"] == "EMAIL_ADDRESS"

    # Scalar-only lists never map to an entity, and neither do scalar leaves.
    assert "records.tags" not in mapping
    assert "notes" not in mapping
    assert "customer_id" not in mapping


def test_json_processor_preserves_structure_order_types_and_lengths(
    customer_export,
):
    analysis = JsonAnalysisBuilder().generate_analysis(customer_export)
    original = copy.deepcopy(customer_export)
    engine = StructuredEngine(JsonDataProcessor())
    operators = {"DEFAULT": OperatorConfig("replace", {"new_value": "REDACTED"})}

    result = engine.anonymize(customer_export, analysis, operators)

    # Structure (including key order), value types and array lengths survive.
    assert list(result) == list(original)
    assert _json_type_shape(result) == _json_type_shape(original)
    assert len(result["records"]) == len(original["records"])

    for original_record, result_record in zip(original["records"], result["records"]):
        assert list(result_record) == list(original_record)
        assert result_record["age"] == original_record["age"]
        assert result_record["verified"] is original_record["verified"]
        assert result_record["nickname"] is None
        assert result_record["tags"] == original_record["tags"]

    # Only mapped string fields are replaced.
    for record in result["records"]:
        assert record["name"] == "REDACTED"
        assert record["ssn"] == "REDACTED"
        assert record["email"] == "REDACTED"
        assert record["phone"] == "REDACTED"
        assert record["manager"]["name"] == "REDACTED"
        assert record["manager"]["email"] == "REDACTED"

    # The input document is returned operated on without being mutated.
    assert customer_export == original


def test_json_processor_applies_operator_to_every_object_in_array(customer_export):
    analysis = JsonAnalysisBuilder().generate_analysis(customer_export)
    engine = StructuredEngine(JsonDataProcessor())
    operators = {"DEFAULT": OperatorConfig("replace", {"new_value": "X"})}

    result = engine.anonymize(customer_export, analysis, operators)

    assert [record["ssn"] for record in result["records"]] == ["X", "X"]
    assert [record["manager"]["email"] for record in result["records"]] == ["X", "X"]


def test_json_processor_handles_top_level_list():
    data = [
        {"name": "John Doe", "meta": {"age": 41}},
        {"name": "Jill Smith", "meta": {"age": 37}},
    ]
    analysis = StructuredAnalysis(entity_mapping={"name": "PERSON"})
    engine = StructuredEngine(JsonDataProcessor())
    operators = {"DEFAULT": OperatorConfig("replace", {"new_value": "REDACTED"})}

    result = engine.anonymize(data, analysis, operators)

    assert isinstance(result, list)
    assert len(result) == 2
    assert [item["name"] for item in result] == ["REDACTED", "REDACTED"]
    assert [item["meta"]["age"] for item in result] == [41, 37]


def test_batch_analyze_and_anonymize_round_trip_on_nested_customer_export(
    customer_export,
):
    analyzer = BatchAnalyzerEngine()
    anonymizer = BatchAnonymizerEngine()

    analysis = list(analyzer.analyze_dict(customer_export, language="en"))
    anonymized = anonymizer.anonymize_dict(analysis)

    # The anonymized document mirrors the input one-for-one.
    assert list(anonymized) == list(customer_export)
    assert _json_type_shape(anonymized) == _json_type_shape(customer_export)
    assert len(anonymized["records"]) == 2

    for original_record, anonymized_record in zip(
        customer_export["records"], anonymized["records"]
    ):
        assert list(anonymized_record) == list(original_record)
        # Non-string scalars keep type and value.
        assert anonymized_record["age"] == original_record["age"]
        assert anonymized_record["verified"] is original_record["verified"]
        assert anonymized_record["nickname"] is None
        # String PII fields are anonymized.
        assert anonymized_record["name"].startswith("<")
        assert anonymized_record["ssn"].startswith("<")
        assert anonymized_record["email"].startswith("<")
        assert anonymized_record["phone"].startswith("<")
        assert anonymized_record["manager"]["name"].startswith("<")
        assert anonymized_record["manager"]["email"].startswith("<")
        # String lists keep their length; PII inside is redacted, the rest
        # is untouched, and an empty list stays empty.
        assert len(anonymized_record["tags"]) == len(original_record["tags"])

    assert anonymized["records"][0]["tags"] == [
        "vip",
        "call <PHONE_NUMBER> soon",
    ]
    assert anonymized["records"][1]["tags"] == []

    assert anonymized["notes"] == customer_export["notes"]
