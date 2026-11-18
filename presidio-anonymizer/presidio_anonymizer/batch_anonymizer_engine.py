from typing import Any, Dict, Iterable, List, Optional, Union

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import DictRecognizerResult, RecognizerResult


class BatchAnonymizerEngine:
    """
    BatchAnonymizerEngine class.

    A class that provides functionality to anonymize in batches.
    :param anonymizer_engine: An instance of the AnonymizerEngine class.
    """

    def __init__(self, anonymizer_engine: Optional[AnonymizerEngine] = None):
        self.anonymizer_engine = anonymizer_engine or AnonymizerEngine()

    def anonymize_list(
        self,
        texts: List[Optional[Union[str, bool, int, float, list, dict]]],
        recognizer_results_list: List[List[RecognizerResult]],
        **kwargs,
    ) -> List[Union[str, Any]]:
        """
        Anonymize a list of values.

        :param texts: List containing the values to be anonymized (original
            values). Scalar items (``str``, ``bool``, ``int``, ``float``) are
            anonymized using the matching recognizer results; nested lists and
            dictionaries are anonymized recursively. Items of any other type
            are returned unchanged.
        :param recognizer_results_list: A list of recognizer results aligned
            positionally with ``texts``. Each element is either a list of
            RecognizerResult (for a scalar item) or a nested list/iterator of
            results (for a nested list/dict). Trailing items without a
            matching entry are anonymized with no recognizer results and
            therefore keep their text.
        :param kwargs: Additional kwargs for the `AnonymizerEngine.anonymize` method
        """
        return_list = []
        if not recognizer_results_list:
            recognizer_results_list = [[] for _ in range(len(texts))]
        for index, text in enumerate(texts):
            recognizer_results = (
                recognizer_results_list[index]
                if index < len(recognizer_results_list)
                else []
            )
            if isinstance(text, (dict, list)):
                return_list.append(
                    self._anonymize_nested(text, recognizer_results, **kwargs)
                )
            elif type(text) in (str, bool, int, float):
                res = self.anonymizer_engine.anonymize(
                    text=str(text),
                    analyzer_results=recognizer_results,
                    **kwargs,
                )
                return_list.append(res.text)
            else:
                # None and values of unsupported types are returned unchanged.
                return_list.append(text)

        return return_list

    def anonymize_dict(
        self, analyzer_results: Iterable[DictRecognizerResult], **kwargs
    ) -> Dict[str, Any]:
        """
        Anonymize values in a dictionary.

        :param analyzer_results: Iterator of `DictRecognizerResult`
        containing the output of the AnalyzerEngine.analyze_dict on the input text.
        :param kwargs: Additional kwargs for the `AnonymizerEngine.anonymize` method
        """

        return_dict = {}
        for result in analyzer_results:
            return_dict[result.key] = self._anonymize_nested(
                result.value, result.recognizer_results, **kwargs
            )
        return return_dict

    def _anonymize_nested(
        self,
        value: Any,
        recognizer_results: Any,
        **kwargs,
    ) -> Any:
        """
        Anonymize a value nested inside a dictionary or list.

        Only strings are sent to the anonymizer engine, so non-string scalar
        values (``int``, ``bool``, ``float``, ``None``) keep their type.
        Dictionaries and lists are traversed recursively and their structure,
        key order and list lengths are preserved.

        :param value: Dictionary, list or scalar value to anonymize.
        :param recognizer_results: Recognizer results aligned with the value.
        :param kwargs: Additional kwargs for the `AnonymizerEngine.anonymize` method
        :return: The anonymized value.
        """
        if isinstance(value, dict):
            return self.anonymize_dict(analyzer_results=recognizer_results, **kwargs)
        if isinstance(value, list):
            if not recognizer_results:
                recognizer_results = [[] for _ in range(len(value))]
            return [
                self._anonymize_nested(
                    item,
                    recognizer_results[index]
                    if index < len(recognizer_results)
                    else [],
                    **kwargs,
                )
                for index, item in enumerate(value)
            ]
        if isinstance(value, str):
            res = self.anonymizer_engine.anonymize(
                text=value, analyzer_results=recognizer_results, **kwargs
            )
            return res.text
        return value
