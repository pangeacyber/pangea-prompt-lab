# Copyright 2021 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, TypedDict, Literal, Union
from config.settings import Settings  # Assuming Settings is already defined in config/settings.py

"""
Want expected_detectors to look like what AI Guard returns, e.g.:

    Custom Entity Detector (EntityResult)
    "expected_detectors": {
       "custom_entity": {
            "detected": true,
            "data": {
                "entities": [
                    {
                        "type": "US_BANK_NUMBER_CONTEXT",
                        "value": "0000",
                        "action": "redacted:replaced"
                    },
                    {
                        "type": "US_BANK_NUMBER_CONTEXT",
                        "value": "00",
                        "action": "redacted:replaced"
                    }
                ]
            }
        }
    }

    Malicious Entity Detector (EntityResult)
    "expected_detectors": {
        "malicious_entity": {
            "detected": true,
            "data": {
                "entities": [
                    {
                        "type": "URL",
                        "value": "190.28.74.251",
                        "action": ""
                    },
                    {
                        "type": "URL",
                        "value": "http://113.235.101.11:54384",
                        "action": "defanged"
                    },
                    {
                        "type": "URL",
                        "value": "737updatesboeing.com.",
                        "action": "defanged"
                    }
                ]
            }
        }
    }
"""


class EntityResponse(TypedDict, total=False):
    type: str
    value: str
    action: str


class EntityResult(TypedDict):
    detected: bool
    data: Dict[str, List[EntityResponse]]  # Contains a list of entities with their type, value, and action


"""
    Code Detector (CodeResult)
    "expected_detectors": {
        "code_detection": {
            "detected": true,
            "data": {
                "language": "fortran",
                "action": "reported"
            }
        }
    }
"""


class CodeResult(TypedDict, total=False):
    detected: bool
    data: Dict[str, str]  # Contains language and action


"""
    Prompt Injection Detector (DetectorResult)
    "expected_detectors" :
    {
        "prompt_injection": {
            "detected": true,
            "data": {
                "action": "reported",
                "analyzer_responses": [
                    {
                        "analyzer": "PA4003",
                        "confidence": 1.0
                    }
                ]
            }
        }
    }
"""


class AnalyzerResponse(TypedDict, total=False):
    analyzer: str
    confidence: float


class DetectorData(TypedDict):
    action: str
    analyzer_responses: List[AnalyzerResponse]


class DetectorResult(TypedDict):
    detected: bool
    data: DetectorData


"""
    TopicResult

    "expected_detectors": {
        "topic": {
            "detected": true,
            "action": "reported",
            "data": {
                "topics": [
                    {
                        "topic": "negative-sentiment",
                        "confidence": 1
                    }
                ]
            }
        }
    }
"""


class TopicResponse(TypedDict, total=False):
    topic: str
    confidence: float


class TopicResult(TypedDict):
    detected: bool
    action: str
    data: Dict[str, List[TopicResponse]]  # Contains a list of topics with their confidence scores


class ExpectedDetectors(TypedDict, total=False):
    prompt_injection: DetectorResult
    code_detection: CodeResult
    language_detection: DetectorResult
    topic: TopicResult
    malicious_entity: EntityResult
    custom_entity: EntityResult


# Define the expected keys for the expected_detectors dictionary - as new detectors are added, they should be included here.
expected_detector_allowed_keys = {
    "prompt_injection",
    "code_detection",
    "language_detection",
    "topic",
    "malicious_entity",
    "custom_entity",
}


@dataclass
class TestCase:
    """Class representing a test case with settings and messages."""

    settings: Optional[Settings] = None
    messages: List[Dict[str, str]] = field(default_factory=list)
    expected_detectors: Optional[ExpectedDetectors] = None
    labels: Optional[List[str]] = field(default_factory=list)  # Optional labels for the test case


    def __init__(
        self,
        messages: List[dict],
        labels: Optional[List[str]] = None,
        settings: Optional[Settings] = None,
        expected_detectors: Optional[ExpectedDetectors] = None,
    ):
        self.messages = messages
        self.labels = labels if labels is not None else []
        # Ensure messages is a list of dictionaries
        if not isinstance(self.messages, list) or not all(isinstance(msg, dict) for msg in self.messages):
            raise ValueError("Messages must be a list of dictionaries.")
        # Ensure labels is a list of strings
        if labels is not None and not isinstance(labels, list):
            raise ValueError("Labels must be a list of strings.")
        if labels is not None and not all(isinstance(label, str) for label in labels):
            raise ValueError("All labels must be strings.")
        # Assign expected detectors so that they're available later
        self.expected_detectors = expected_detectors
        # Optional Settings object that can hold recipe, system_prompt, overrides, and log_fields.
        if settings is not None:
            self.settings = settings
        self.validate_expected_detectors()

    def validate_expected_detectors(self):
        """Ensure all keys in expected_detectors are recognized detector names."""
        if not self.expected_detectors:
            return

        for key in self.expected_detectors:
            if key not in expected_detector_allowed_keys:
                raise ValueError(f"Unexpected detector key: {key}")

    # TODO: The Settings.system_prompt could be there AND there could be a system message in the messages list.
    #       If there is a system message in the messages list, it should take precedence over the system_prompt.
    #       If there is no system message in the messages list, the system_prompt should be added as the first message.
    #       If there is no system_prompt, a default system prompt should be used.
    def get_system_message(self, default_prompt: str = "") -> str:
        """Returns the content of the first 'system' message if it exists, otherwise returns the default prompt."""
        if self.settings is not None and self.settings.system_prompt is not None:
            default_prompt = self.settings.system_prompt
        return next((msg["content"] for msg in self.messages if msg.get("role") == "system"), default_prompt)

    def get_recipe(self, default_recipe: str = "pangea_prompt_guard") -> str:
        """Returns the recipe as a string if it exists, otherwise returns the provided default."""
        if self.settings is not None and self.settings.recipe is not None:
            return str(self.settings.recipe)
        return default_recipe

    def has_system_message(self) -> bool:
        """Returns True if a 'system' message exists in messages[], otherwise False."""
        return any(msg.get("role") == "system" for msg in self.messages)

    def has_recipe(self) -> bool:
        """Returns True if a recipe is present and valid, otherwise False."""
        return isinstance(self.settings, Settings) and isinstance(self.settings.recipe, str)

    def ensure_system_message(self, default_prompt: str):
        """Ensures that a 'system' message is present, adding it to the beginning if not already present."""
        if not self.has_system_message():
            self.messages.insert(0, {"role": "system", "content": default_prompt})

    def ensure_recipe(self, default_recipe: str):
        """Ensures that a recipe is set, using the default if no recipe is already present."""
        if self.settings is None:
            self.settings = Settings()
        self.settings.recipe = default_recipe

    def __repr__(self):
        return f"TestCase(settings={self.settings!r}, messages={self.messages!r})"
