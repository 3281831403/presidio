import collections.abc
import logging
from collections import deque
from typing import Any, Deque, Dict, Iterable, Iterator, List, Optional, Tuple, Union

from presidio_analyzer import AnalyzerEngine, DictAnalyzerResult, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts

logger = logging.getLogger("presidio-analyzer")

# JSON-like scalar types handled by the batch analyzer. Every other value
# (custom objects, sets, generators, ...) is rejected as unsupported.
SCALAR_TYPES = (str, int, bool, float)


class BatchAnalyzerEngine:
    """
    Batch analysis of documents (tables, lists, dicts).

    Wrapper class to run Presidio Analyzer Engine on multiple values,
    either lists/iterators of strings, or dictionaries.

    :param analyzer_engine: AnalyzerEngine instance to use
    for handling the values in those collections.
    """

    def __init__(self, analyzer_engine: Optional[AnalyzerEngine] = None):
        self.analyzer_engine = analyzer_engine
        if not analyzer_engine:
            self.analyzer_engine = AnalyzerEngine()

    def analyze_iterator(
        self,
        texts: Iterable[Union[str, bool, float, int]],
        language: str,
        batch_size: int = 1,
        n_process: int = 1,
        **kwargs,
    ) -> List[List[RecognizerResult]]:
        """
        Analyze an iterable of strings.

        :param texts: An list containing strings to be analyzed.
        :param language: Input language
        :param batch_size: Batch size to process in a single iteration
        :param n_process: Number of processors to use. Defaults to `1`
        :param kwargs: Additional parameters for the `AnalyzerEngine.analyze` method.
        (default value depends on the nlp engine implementation)
        """

        # validate types
        texts = self._validate_types(texts)

        # analyze() works on the normalized text, so the NLP engine has to process
        # that text. The original values are queued to be passed to analyze() in
        # the same order. analyze() normalizes each text again, which gives the
        # same text the artifacts were computed on.
        original_texts: Deque[Any] = deque()
        texts = self._normalize_texts(texts, original_texts, language)

        # Process the texts as batch for improved performance
        nlp_artifacts_batch: Iterator[Tuple[str, NlpArtifacts]] = (
            self.analyzer_engine.nlp_engine.process_batch(
                texts=texts,
                language=language,
                batch_size=batch_size,
                n_process=n_process,
            )
        )

        list_results = []
        for _, nlp_artifacts in nlp_artifacts_batch:
            text = original_texts.popleft()
            results = self.analyzer_engine.analyze(
                text=str(text), nlp_artifacts=nlp_artifacts, language=language, **kwargs
            )

            list_results.append(results)

        return list_results

    def analyze_dict(
        self,
        input_dict: Dict[str, Union[Any, Iterable[Any]]],
        language: str,
        keys_to_skip: Optional[List[str]] = None,
        batch_size: int = 1,
        n_process: int = 1,
        **kwargs,
    ) -> Iterator[DictAnalyzerResult]:
        """
        Analyze a dictionary of keys (strings) and values of any JSON-like type.

        Values can be scalars (str, int, bool, float), nested dictionaries or
        lists, including lists of nested dictionaries/lists. Non-string and
        empty values are returned without recognizer results.

        :param input_dict: The input dictionary for analysis
        :param language: Input language
        :param keys_to_skip: Keys to ignore during analysis. Nested keys are
        addressed with a dotted path (e.g. ``"address.city"``); a key skipped
        inside a list is skipped in every element of that list.
        :param batch_size: Batch size to process in a single iteration
        :param n_process: Number of processors to use. Defaults to `1`

        :param kwargs: Additional keyword arguments
        for the `AnalyzerEngine.analyze` method.
        Use this to pass arguments to the analyze method,
        such as `ad_hoc_recognizers`, `context`, `return_decision_process`.
        See `AnalyzerEngine.analyze` for the full list.
        """

        context = []
        if "context" in kwargs:
            context = kwargs["context"]
            del kwargs["context"]

        if not keys_to_skip:
            keys_to_skip = []

        for key, value in input_dict.items():
            if not value or key in keys_to_skip:
                yield DictAnalyzerResult(key=key, value=value, recognizer_results=[])
                continue  # skip this key as requested

            # Add the key as an additional context
            specific_context = context[:]
            specific_context.append(key)

            results = self._analyze_value(
                value=value,
                language=language,
                context=specific_context,
                keys_to_skip=self._get_nested_keys_to_skip(key, keys_to_skip),
                batch_size=batch_size,
                n_process=n_process,
                **kwargs,
            )

            yield DictAnalyzerResult(key=key, value=value, recognizer_results=results)

    def _analyze_value(
        self,
        value: Any,
        language: str,
        context: List[str],
        keys_to_skip: List[str],
        batch_size: int,
        n_process: int,
        **kwargs,
    ) -> Union[List[RecognizerResult], Iterator[DictAnalyzerResult], List[Any]]:
        """Analyze a single dictionary value of any supported JSON-like type."""
        if type(value) in SCALAR_TYPES:
            return self.analyzer_engine.analyze(
                text=str(value),
                language=language,
                context=context,
                **kwargs,
            )
        if isinstance(value, dict):
            return self.analyze_dict(
                input_dict=value,
                language=language,
                context=context,
                keys_to_skip=keys_to_skip,
                batch_size=batch_size,
                n_process=n_process,
                **kwargs,
            )
        if isinstance(value, list):
            return self._analyze_list(
                values=value,
                language=language,
                context=context,
                keys_to_skip=keys_to_skip,
                batch_size=batch_size,
                n_process=n_process,
                **kwargs,
            )
        if isinstance(value, collections.abc.Iterable):
            # Other iterables (tuples, sets, ...) only ever held primitives;
            # keep routing them through the flat NLP batch pipeline.
            return self.analyze_iterator(
                texts=value,
                language=language,
                context=context,
                n_process=n_process,
                batch_size=batch_size,
                **kwargs,
            )
        raise ValueError(f"type {type(value)} is unsupported.")

    def _analyze_list(
        self,
        values: List[Any],
        language: str,
        context: List[str],
        keys_to_skip: List[str],
        batch_size: int,
        n_process: int,
        **kwargs,
    ) -> List[Any]:
        """
        Analyze a list, preserving its order and length.

        Scalar runs are analyzed together through the NLP batch pipeline while
        nested dictionaries and lists are analyzed recursively. The result for
        each element aligns positionally with the input element.
        """
        results: List[Any] = []
        scalar_run: List[Any] = []
        scalar_run_indexes: List[int] = []

        def flush_scalar_run() -> None:
            if not scalar_run:
                return
            scalar_results = self.analyze_iterator(
                texts=scalar_run,
                language=language,
                context=context,
                n_process=n_process,
                batch_size=batch_size,
                **kwargs,
            )
            for index, scalar_result in zip(scalar_run_indexes, scalar_results):
                results[index] = scalar_result
            scalar_run.clear()
            scalar_run_indexes.clear()

        for value in values:
            if value is None or type(value) in SCALAR_TYPES:
                # analyze_iterator handles None and empty values as no-results.
                scalar_run.append(value)
                scalar_run_indexes.append(len(results))
                results.append(None)
            elif isinstance(value, dict):
                flush_scalar_run()
                results.append(
                    self.analyze_dict(
                        input_dict=value,
                        language=language,
                        context=context,
                        keys_to_skip=keys_to_skip,
                        batch_size=batch_size,
                        n_process=n_process,
                        **kwargs,
                    )
                )
            elif isinstance(value, list):
                flush_scalar_run()
                results.append(
                    self._analyze_list(
                        values=value,
                        language=language,
                        context=context,
                        keys_to_skip=keys_to_skip,
                        batch_size=batch_size,
                        n_process=n_process,
                        **kwargs,
                    )
                )
            else:
                raise ValueError(f"type {type(value)} is unsupported.")

        flush_scalar_run()
        return results

    def _normalize_texts(
        self, texts: Iterable[Any], original_texts: Deque[Any], language: str
    ) -> Iterator[Any]:
        text_normalizer = self.analyzer_engine.text_normalizer
        for text in texts:
            original_texts.append(text)
            if isinstance(text, str):
                text = text_normalizer.normalize(text, language).text
            yield text

    @staticmethod
    def _validate_types(value_iterator: Iterable[Any]) -> Iterator[Any]:
        for val in value_iterator:
            if val and type(val) not in (int, float, bool, str):
                err_msg = (
                    "Analyzer.analyze_iterator only works "
                    "on primitive types (int, float, bool, str). "
                    "Analyze nested objects through analyze_dict."
                )
                logger.error(err_msg)
                raise ValueError(err_msg)
            yield val

    @staticmethod
    def _get_nested_keys_to_skip(key, keys_to_skip):
        new_keys_to_skip = [
            k.replace(f"{key}.", "") for k in keys_to_skip if k.startswith(key)
        ]
        return new_keys_to_skip
