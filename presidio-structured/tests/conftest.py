"""Pytest fixtures for presidio-structured tests."""

import pandas as pd
import pytest
from presidio_anonymizer.entities import OperatorConfig
from presidio_structured import PandasAnalysisBuilder, JsonAnalysisBuilder
from presidio_structured.config import StructuredAnalysis


@pytest.fixture
def sample_df():
    data = {
        "name": ["John Doe", "Jane Doe", "John Smith"],
        "email": [
            "john@example.com",
            "jane@example.com",
            "johnsmith@example.com",
        ],
        "phone": ["(212) 456-7890", "(213) 456-7590", "(214) 456-2830"],
    }
    return pd.DataFrame(data)


@pytest.fixture
def sample_df_strategy():
    data = {
        "name": ["John Doe", "Jane Smith", "Alice Johnson"],
        "email": ["john.doe@example.com", "jane.smith@example.com", "alice.johnson@example.com"],
        "city": ["Anytown", "Somewhere", "Elsewhere"],
        "state": ["CA", "TX", "NY"],
        "non_pii": ["reallynotpii", "reallynotapii", "reallynotapiiatall"],
    }

    return pd.DataFrame(data)


@pytest.fixture
def sample_json():
    data = {
        "id": 1,
        "name": "John Doe",
        "email": "john.doe@example.com",
        "address": {
            "street": "123 Main St",
            "city": "Anytown",
            "state": "CA",
            "non_pii": "nonpii",
        },
    }
    return data


@pytest.fixture
def sample_json_with_array():
    data = {
        "users": [
            {"id": 1, "name": "John Doe"},
            {"id": 2, "name": "Jane Doe"},
        ]
    }
    return data


@pytest.fixture
def json_analysis_builder():
    return JsonAnalysisBuilder()


@pytest.fixture
def tabular_analysis_builder():
    return PandasAnalysisBuilder()


@pytest.fixture
def operators():
    return {
        "PERSON": OperatorConfig("replace", {"new_value": "PERSON_REPLACEMENT"}),
        "DEFAULT": OperatorConfig("replace", {"new_value": "DEFAULT_REPLACEMENT"}),
    }


@pytest.fixture
def operators_no_default():
    return {
        "PERSON": OperatorConfig("replace", {"new_value": "PERSON_REPLACEMENT"}),
    }


@pytest.fixture
def tabular_analysis():
    return StructuredAnalysis(
        entity_mapping={
            "name": "PERSON",
            "email": "EMAIL_ADDRESS",
            "phone": "PHONE_NUMBER",
        }
    )


@pytest.fixture
def json_analysis():
    return StructuredAnalysis(
        entity_mapping={
            "name": "PERSON",
            "address.city": "LOCATION",
        }
    )


@pytest.fixture
def customer_export():
    """Nested customer JSON mixing objects, object arrays and JSON scalars."""
    return {
        "customer_id": 1042,
        "active": True,
        "nickname": None,
        "records": [
            {
                "name": "John Doe",
                "ssn": "716-41-5362",
                "email": "john.doe@example.com",
                "phone": "(212) 456-7890",
                "age": 41,
                "verified": True,
                "nickname": None,
                "tags": ["vip", "call 212-555-0143 soon"],
                "manager": {"name": "Jane Roe", "email": "jane.roe@example.com"},
            },
            {
                "name": "Jill Smith",
                "ssn": "987-65-4321",
                "email": "jill.smith@example.com",
                "phone": "(617) 555-0132",
                "age": 37,
                "verified": False,
                "nickname": None,
                "tags": [],
                "manager": {"name": "Joan Bell", "email": "joan.bell@example.com"},
            },
        ],
        "notes": ["plain note", "another plain note"],
    }
