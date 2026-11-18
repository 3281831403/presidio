# ruff: noqa: D101,D102,D103,I001

import pytest

from presidio_anonymizer import BatchAnonymizerEngine, BatchDeanonymizeEngine
from presidio_anonymizer.deanonymize_engine import DeanonymizeEngine
from presidio_anonymizer.entities import (
    DictRecognizerResult,
    EngineResult,
    OperatorConfig,
    OperatorResult,
    RecognizerResult,
)
from presidio_anonymizer.operators import Decrypt


ENCRYPTED_TEXT = "My name is S184CMt9Drj7QaKQ21JTrpYzghnboTF9pn/neN8JME0="
DECRYPTED_TEXT = "My name is Chloë"
ENTITY = OperatorResult(start=11, end=55, entity_type="PERSON")
OPERATORS = {"DEFAULT": OperatorConfig(Decrypt.NAME, {"key": "WmZq4t7w!z%C&F)J"})}


@pytest.fixture(scope="module")
def engine():
    return BatchDeanonymizeEngine()


def test_package_root_exports_batch_deanonymize_engine():
    from presidio_anonymizer import (
        BatchDeanonymizeEngine as ExportedBatchDeanonymizeEngine,
    )

    assert ExportedBatchDeanonymizeEngine is BatchDeanonymizeEngine


def test_given_analyzer_result_we_deanonymize_list_correctly(engine):
    texts = [ENCRYPTED_TEXT, ENCRYPTED_TEXT]
    entities_list = [[ENTITY], [ENTITY]]

    deanonymize_results = engine.deanonymize_list(
        texts=texts, entities_list=entities_list, operators=OPERATORS
    )

    assert deanonymize_results == [DECRYPTED_TEXT, DECRYPTED_TEXT]


def test_given_analyzer_result_we_deanonymize_dict_correctly(engine):
    analyzer_results = [
        DictRecognizerResult(
            key="name", value=ENCRYPTED_TEXT, recognizer_results=[ENTITY]
        )
    ]

    deanonymize_results = engine.deanonymize_dict(
        anonymizer_results=analyzer_results, operators=OPERATORS
    )

    assert deanonymize_results == {"name": DECRYPTED_TEXT}


def test_given_nested_analyzer_result_we_deanonymize_dict_correctly(engine):
    analyzer_results = [
        DictRecognizerResult(
            key="customer",
            value={"profile": {"name": ENCRYPTED_TEXT}},
            recognizer_results=[
                DictRecognizerResult(
                    key="profile",
                    value={"name": ENCRYPTED_TEXT},
                    recognizer_results=[
                        DictRecognizerResult(
                            key="name",
                            value=ENCRYPTED_TEXT,
                            recognizer_results=[ENTITY],
                        )
                    ],
                )
            ],
        )
    ]

    deanonymize_results = engine.deanonymize_dict(
        anonymizer_results=analyzer_results, operators=OPERATORS
    )

    assert deanonymize_results == {"customer": {"profile": {"name": DECRYPTED_TEXT}}}


def test_given_empty_entities_we_return_text_unchanged(engine):
    deanonymize_results = engine.deanonymize_list(
        texts=[ENCRYPTED_TEXT], entities_list=[], operators=OPERATORS
    )

    assert deanonymize_results == [ENCRYPTED_TEXT]


def test_given_short_entities_list_we_keep_trailing_texts(engine):
    deanonymize_results = engine.deanonymize_list(
        texts=[ENCRYPTED_TEXT, "plain trailing text"],
        entities_list=[[ENTITY]],
        operators=OPERATORS,
    )

    assert deanonymize_results == [DECRYPTED_TEXT, "plain trailing text"]


def test_given_exact_type_list_values_we_route_through_injected_engine():
    deanonymize_engine = RecordingDeanonymizeEngine()
    engine = BatchDeanonymizeEngine(deanonymize_engine=deanonymize_engine)

    sentinel = object()
    deanonymize_results = engine.deanonymize_list(
        texts=[True, 7, 1.5, sentinel],
        entities_list=[[], [], [], []],
        operators=OPERATORS,
    )

    assert deanonymize_results == ["custom::True", "custom::7", "custom::1.5", sentinel]
    assert deanonymize_engine.calls == [
        ("True", [], OPERATORS),
        ("7", [], OPERATORS),
        ("1.5", [], OPERATORS),
    ]


def test_given_non_string_list_value_we_return_item_unchanged(engine):
    analyzer_results = [
        DictRecognizerResult(
            key="items",
            value=[ENCRYPTED_TEXT, [ENCRYPTED_TEXT, 123, True], object()],
            recognizer_results=[[ENTITY], [[ENTITY], [], []], []],
        )
    ]

    deanonymize_results = engine.deanonymize_dict(
        anonymizer_results=analyzer_results, operators=OPERATORS
    )

    assert deanonymize_results["items"][0] == DECRYPTED_TEXT
    # Nested lists are traversed recursively; non-string elements keep type.
    assert deanonymize_results["items"][1] == [DECRYPTED_TEXT, 123, True]
    assert type(deanonymize_results["items"][2]) is object


def test_given_list_of_objects_we_deanonymize_every_field(engine):
    analyzer_results = [
        DictRecognizerResult(
            key="records",
            value=[
                {"name": ENCRYPTED_TEXT, "id": 1},
                {"name": ENCRYPTED_TEXT, "id": 2},
            ],
            recognizer_results=[
                [
                    DictRecognizerResult(
                        key="name",
                        value=ENCRYPTED_TEXT,
                        recognizer_results=[ENTITY],
                    ),
                    DictRecognizerResult(key="id", value=1, recognizer_results=[]),
                ],
                [
                    DictRecognizerResult(
                        key="name",
                        value=ENCRYPTED_TEXT,
                        recognizer_results=[ENTITY],
                    ),
                    DictRecognizerResult(key="id", value=2, recognizer_results=[]),
                ],
            ],
        )
    ]

    deanonymize_results = engine.deanonymize_dict(
        anonymizer_results=analyzer_results, operators=OPERATORS
    )

    assert deanonymize_results == {
        "records": [
            {"name": DECRYPTED_TEXT, "id": 1},
            {"name": DECRYPTED_TEXT, "id": 2},
        ]
    }


def test_given_wrong_key_we_fail_instead_of_silently_returning_ciphertext(engine):
    wrong_key_operators = {
        "DEFAULT": OperatorConfig(Decrypt.NAME, {"key": "1234567890abcdef"})
    }
    analyzer_results = [
        DictRecognizerResult(
            key="records",
            value=[{"name": ENCRYPTED_TEXT}],
            recognizer_results=[
                [
                    DictRecognizerResult(
                        key="name",
                        value=ENCRYPTED_TEXT,
                        recognizer_results=[ENTITY],
                    )
                ]
            ],
        )
    ]

    with pytest.raises(Exception):
        engine.deanonymize_dict(
            anonymizer_results=analyzer_results, operators=wrong_key_operators
        )


def test_given_scalar_dict_value_we_return_value_unchanged(engine):
    analyzer_results = [
        DictRecognizerResult(key="id", value=123, recognizer_results=[])
    ]

    deanonymize_results = engine.deanonymize_dict(
        anonymizer_results=analyzer_results, operators=OPERATORS
    )

    assert deanonymize_results == {"id": 123}


class RecordingDeanonymizeEngine(DeanonymizeEngine):
    def __init__(self):
        super().__init__()
        self.calls = []

    def deanonymize(self, text, entities, operators):
        self.calls.append((text, entities, operators))
        return EngineResult(text=f"custom::{text}")


def test_given_custom_deanonymizer_we_use_injected_engine():
    deanonymize_engine = RecordingDeanonymizeEngine()
    engine = BatchDeanonymizeEngine(deanonymize_engine=deanonymize_engine)

    deanonymize_results = engine.deanonymize_list(
        texts=[ENCRYPTED_TEXT], entities_list=[[ENTITY]], operators=OPERATORS
    )

    assert deanonymize_results == [f"custom::{ENCRYPTED_TEXT}"]
    assert deanonymize_engine.calls == [(ENCRYPTED_TEXT, [ENTITY], OPERATORS)]


def test_given_unsupported_kwargs_then_batch_api_rejects_them(engine):
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        engine.deanonymize_list(
            texts=[ENCRYPTED_TEXT],
            entities_list=[[ENTITY]],
            operators=OPERATORS,
            language="en",
        )


CRYPTO_KEY = "WmZq4t7w!z%C&F)J"
WRONG_CRYPTO_KEY = "1234567890abcdef"

CUSTOMER_DOCUMENT = {
    "customer_id": 1042,
    "active": True,
    "nickname": None,
    "records": [
        {
            "name": "John Doe",
            "age": 41,
            "verified": True,
            "nickname": None,
            "tags": ["vip", "call back soon"],
            "manager": {"name": "Jane Roe"},
        },
        {
            "name": "Jill Smith",
            "age": 37,
            "verified": False,
            "nickname": None,
            "tags": [],
            "manager": {"name": "Joan Bell"},
        },
    ],
    "notes": ["plain note", "another plain note"],
}


def _build_analyzer_results(value):
    """Build full-span recognizer results for every string leaf."""
    if isinstance(value, dict):
        return [
            DictRecognizerResult(key, item, _build_analyzer_results(item))
            for key, item in value.items()
        ]
    if isinstance(value, list):
        return [_build_analyzer_results(item) for item in value]
    if isinstance(value, str):
        return [RecognizerResult("PERSON", 0, len(value), 0.9)]
    return []


def _build_decrypt_entities(value):
    """Build full-span decrypt entities for every encrypted string leaf."""
    if isinstance(value, dict):
        return [
            DictRecognizerResult(key, item, _build_decrypt_entities(item))
            for key, item in value.items()
        ]
    if isinstance(value, list):
        return [_build_decrypt_entities(item) for item in value]
    if isinstance(value, str):
        return [OperatorResult(0, len(value), "PERSON")]
    return []


def test_encrypt_then_batch_decrypt_restores_every_field_in_nested_document():
    batch_anonymizer = BatchAnonymizerEngine()
    batch_deanonymizer = BatchDeanonymizeEngine()
    encrypt_operators = {"DEFAULT": OperatorConfig("encrypt", {"key": CRYPTO_KEY})}
    decrypt_operators = {"DEFAULT": OperatorConfig(Decrypt.NAME, {"key": CRYPTO_KEY})}

    encrypted = batch_anonymizer.anonymize_dict(
        _build_analyzer_results(CUSTOMER_DOCUMENT),
        operators=encrypt_operators,
    )
    decrypted = batch_deanonymizer.deanonymize_dict(
        _build_decrypt_entities(encrypted), operators=decrypt_operators
    )

    # Every field is restored to its original value, type and position.
    assert decrypted == CUSTOMER_DOCUMENT
    assert type(decrypted["customer_id"]) is int
    assert type(decrypted["active"]) is bool
    assert decrypted["nickname"] is None
    assert len(decrypted["records"]) == 2

    # The encrypted document really held ciphertext in the string fields.
    assert encrypted["records"][0]["name"] != "John Doe"
    assert encrypted["notes"][0] != "plain note"


def test_batch_decrypt_with_wrong_key_fails_on_nested_document():
    batch_anonymizer = BatchAnonymizerEngine()
    batch_deanonymizer = BatchDeanonymizeEngine()
    encrypted = batch_anonymizer.anonymize_dict(
        _build_analyzer_results(CUSTOMER_DOCUMENT),
        operators={"DEFAULT": OperatorConfig("encrypt", {"key": CRYPTO_KEY})},
    )
    wrong_key_operators = {
        "DEFAULT": OperatorConfig(Decrypt.NAME, {"key": WRONG_CRYPTO_KEY})
    }

    # A wrong key must raise rather than silently returning the ciphertext.
    with pytest.raises(Exception):
        batch_deanonymizer.deanonymize_dict(
            _build_decrypt_entities(encrypted),
            operators=wrong_key_operators,
        )
