from dataclasses import dataclass
from typing import Any, Iterator, List, Union

from presidio_analyzer import RecognizerResult


@dataclass
class DictAnalyzerResult:
    """
    Data class for holding the output of the Presidio Analyzer on dictionaries.

    :param key: key in dictionary
    :param value: value to run analysis on (a scalar, list or dictionary)
    :param recognizer_results: Analyzer output for one value.
    Could be either:
     - A list of recognizer results if the input is one scalar value
     - A list aligned with the input list if the input is a list. Each element
       is a list of recognizer results for a scalar item, an iterator of
       DictAnalyzerResult for a dictionary item, or another such nested list
       for a nested list.
     - An iterator of a DictAnalyzerResult, if the input is a dictionary.
       In this case the recognizer_results would be the iterator
       of the DictAnalyzerResults next level in the dictionary.
    """

    key: str
    value: Union[str, List[Any], dict]
    recognizer_results: Union[
        List[RecognizerResult],
        List[Any],
        Iterator["DictAnalyzerResult"],
    ]
