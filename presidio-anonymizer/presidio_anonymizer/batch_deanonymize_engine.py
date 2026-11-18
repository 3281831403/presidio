from typing import Any, Dict, Iterable, List, Optional, Union

from presidio_anonymizer.deanonymize_engine import DeanonymizeEngine
from presidio_anonymizer.entities import (
    DictRecognizerResult,
    OperatorConfig,
    OperatorResult,
)


class BatchDeanonymizeEngine:
    """
    BatchDeanonymizeEngine class.

    A class that provides functionality to deanonymize in batches.
    :param deanonymize_engine: An instance of the DeanonymizeEngine class.
    """

    def __init__(self, deanonymize_engine: Optional[DeanonymizeEngine] = None):
        self.deanonymize_engine = deanonymize_engine or DeanonymizeEngine()

    def deanonymize_list(
        self,
        texts: List[Optional[Union[str, bool, int, float, list, dict]]],
        entities_list: List[List[OperatorResult]],
        operators: Dict[str, OperatorConfig],
    ) -> List[Union[str, Any]]:
        """
        Deanonymize a list of values.

        :param texts: List containing the values to be deanonymized. Scalar
            items (``str``, ``bool``, ``int``, ``float``) are deanonymized
            using the matching entities; nested lists and dictionaries are
            deanonymized recursively. Items of any other type are left
            unchanged.
        :param entities_list: A list of entities used as the deanonymization
            input spans, aligned positionally with ``texts``. If the list is
            shorter than ``texts``, the trailing texts are returned unchanged
            rather than dropped.
        :param operators: Operators to define the deanonymization type.
        """
        return_list = []
        if not entities_list:
            entities_list = [[] for _ in range(len(texts))]
        for index, text in enumerate(texts):
            entities = entities_list[index] if index < len(entities_list) else []
            if isinstance(text, (dict, list)):
                return_list.append(self._deanonymize_nested(text, entities, operators))
            elif type(text) in (str, bool, int, float):
                res = self.deanonymize_engine.deanonymize(
                    text=str(text), entities=entities, operators=operators
                )
                return_list.append(res.text)
            else:
                # None and values of unsupported types are returned unchanged.
                return_list.append(text)

        return return_list

    def deanonymize_dict(
        self,
        anonymizer_results: Iterable[DictRecognizerResult],
        operators: Dict[str, OperatorConfig],
    ) -> Dict[str, Any]:
        """
        Deanonymize values in a dictionary.

        :param anonymizer_results: Iterator of `DictRecognizerResult`
            containing the output of batch anonymization on the input text.
        :param operators: Operators to define the deanonymization type.
        """

        return_dict = {}
        for result in anonymizer_results:
            return_dict[result.key] = self._deanonymize_nested(
                result.value, result.recognizer_results, operators
            )
        return return_dict

    def _deanonymize_nested(
        self,
        value: Any,
        recognizer_results: Any,
        operators: Dict[str, OperatorConfig],
    ) -> Any:
        """
        Deanonymize a value nested inside a dictionary or list.

        Only strings are sent to the deanonymize engine, so non-string scalar
        values (``int``, ``bool``, ``float``, ``None``) keep their type.
        Dictionaries and lists are traversed recursively and their structure,
        key order and list lengths are preserved. A failed decryption (wrong
        key or corrupted ciphertext) propagates the engine's exception rather
        than returning the value unchanged.

        :param value: Dictionary, list or scalar value to deanonymize.
        :param recognizer_results: Entities aligned with the value.
        :param operators: Operators to define the deanonymization type.
        :return: The deanonymized value.
        """
        if isinstance(value, dict):
            return self.deanonymize_dict(
                anonymizer_results=recognizer_results, operators=operators
            )
        if isinstance(value, list):
            if not recognizer_results:
                recognizer_results = [[] for _ in range(len(value))]
            return [
                self._deanonymize_nested(
                    item,
                    recognizer_results[index]
                    if index < len(recognizer_results)
                    else [],
                    operators,
                )
                for index, item in enumerate(value)
            ]
        if isinstance(value, str):
            res = self.deanonymize_engine.deanonymize(
                text=value, entities=recognizer_results, operators=operators
            )
            return res.text
        return value
