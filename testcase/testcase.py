# Copyright 2021 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from dataclasses import dataclass, field
from typing import List, Optional, Dict
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


@dataclass
class EntityResponse:
    type: str
    value: str
    action: str

@dataclass
class EntityResult:
    detected: bool = False
    data: Dict[str, List[EntityResponse]] = field(default_factory=dict)

@dataclass
class CodeResult:
    detected: bool = False
    data: Dict[str, str] = field(default_factory=dict)

@dataclass
class AnalyzerResponse:
    analyzer: str
    confidence: float

@dataclass
class DetectorData:
    action: str
    analyzer_responses: List[AnalyzerResponse] = field(default_factory=list)

@dataclass
class DetectorResult:
    detected: bool = False
    data: DetectorData = field(default_factory=DetectorData)


# Re-insert the TopicResponse class
@dataclass
class TopicResponse:
    topic: str
    confidence: float

@dataclass
class TopicResult:
    detected: bool = False
    topics: List[TopicResponse] = field(default_factory=list)
    action: str = ""
    @property
    def data(self) -> Dict[str, List[TopicResponse]]:
        return {"topics": self.topics}
@dataclass
class ExpectedDetectors:
    prompt_injection: Optional[DetectorResult]    = None
    code_detection:   Optional[CodeResult]        = None
    language_detection: Optional[DetectorResult]  = None
    topic:            Optional[TopicResult]        = None
    malicious_entity: Optional[EntityResult]      = None
    custom_entity:    Optional[EntityResult]      = None


@dataclass
class TestCase:
    """Class representing a test case with settings and messages."""

    settings: Optional[Settings] = None
    messages: List[Dict[str, str]] = field(default_factory=list)
    expected_detectors: ExpectedDetectors = field(default_factory=ExpectedDetectors)
    labels: Optional[List[str]] = field(default_factory=list)  # Optional labels for the test case
    # Fields that will only be used to track the detectors seen during the test case execution
    # This is not part of the expected output, but is useful for runtime checks
    # detectors_seen and not_seen are now in the ExpectedDetectors FailedTestCase class
    # detectors_seen: Optional[List[str]] = field(default_factory=list)  # Detectors that have been seen in the test case
    # detectors_not_seen: Optional[List[str]] = field(default_factory=list)  # Detectors that were expected but not seen in the test case
    index: Optional[int] = None  # Optional index of the test case in the input, useful for tracking

    def __init__(
        self,
        messages: List[dict],
        labels: Optional[List[str]] = None,
        settings: Optional[Settings] = None,
        expected_detectors: Optional[dict] = None,
    ):
        self.messages = messages
        self.labels = labels if labels is not None else []
        # self.detectors_seen = []
        # self.detectors_not_seen = []
        # Ensure messages is a list of dictionaries
        if not isinstance(self.messages, list) or not all(isinstance(msg, dict) for msg in self.messages):
            raise ValueError("Messages must be a list of dictionaries.")
        # Ensure labels is a list of strings
        if labels is not None and not isinstance(labels, list):
            raise ValueError("Labels must be a list of strings.")
        if labels is not None and not all(isinstance(label, str) for label in labels):
            raise ValueError("All labels must be strings.")
        # Optional Settings object that can hold recipe, system_prompt, overrides, and log_fields.
        if settings is not None:
            self.settings = settings
        if expected_detectors:
            ed = ExpectedDetectors()
            for name, value in expected_detectors.items():
                if name == "prompt_injection" and value is not None:
                    ed.prompt_injection = DetectorResult(
                        detected=value.get("detected", False),
                        data=DetectorData(
                            action=value["data"].get("action", ""),
                            analyzer_responses=[
                                AnalyzerResponse(
                                    analyzer=ar.get("analyzer", ""),
                                    confidence=ar.get("confidence", 0.0),
                                )
                                for ar in value["data"].get("analyzer_responses", [])
                            ],
                        ),
                    )
                elif name == "code_detection" and value is not None:
                    ed.code_detection = CodeResult(
                        detected=value.get("detected", False),
                        data=value["data"],
                    )
                elif name == "language_detection" and value is not None:
                    ed.language_detection = DetectorResult(
                        detected=value.get("detected", False),
                        data=DetectorData(
                            action=value["data"].get("action", ""),
                            analyzer_responses=[
                                AnalyzerResponse(
                                    analyzer=ar.get("analyzer", ""),
                                    confidence=ar.get("confidence", 0.0),
                                )
                                for ar in value["data"].get("analyzer_responses", [])
                            ],
                        ),
                    )
                elif name == "topic" and value is not None:
                    ed.topic = TopicResult(
                        detected=value.get("detected", False),
                        action=value.get("action", ""),
                        topics=[
                            TopicResponse(
                                topic=tr.get("topic", ""),
                                confidence=tr.get("confidence", 0.0),
                            )
                            for tr in value["data"].get("topics", [])
                        ],
                    )
                elif name in ("malicious_entity", "custom_entity") and value is not None:
                    setattr(ed, name, EntityResult(
                        detected=value.get("detected", False),
                        data={
                            "entities": [
                                EntityResponse(**er)
                                for er in value["data"].get("entities", [])
                            ]
                        },
                    ))
            self.expected_detectors = ed
        else:
            self.expected_detectors = ExpectedDetectors()

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
