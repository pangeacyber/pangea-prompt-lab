# Copyright 2021 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from dataclasses import dataclass
from typing import Optional
from .detectors import (
    CodeDetection,
    Competitors,
    # CustomEntity
    LanguageDetection,
    MaliciousEntity,
    PIIEntity,
    PromptInjection,
    SecretsDetection,
    Topic,
)


@dataclass
class Overrides:
    ignore_recipe: Optional[bool] = None
    code_detection: Optional[CodeDetection] = None
    competitors: Optional[Competitors] = None
    # custom_entity: Optional[CustomEntity] = None
    language_detection: Optional[LanguageDetection] = None
    malicious_entity: Optional[MaliciousEntity] = None
    pii_entity: Optional[PIIEntity] = None
    prompt_injection: Optional[PromptInjection] = None
    secrets_detection: Optional[SecretsDetection] = None
    topic: Optional[Topic] = None

    def get_enabled_detector_labels(self) -> list[str]:
        detector_labels: list[str] = []

        if self.code_detection and getattr(self.code_detection, "disabled", False) is not True:
            detector_labels.append("code")
        if self.competitors and getattr(self.competitors, "disabled", False) is not True:
            detector_labels.append("competitor")
        if self.language_detection and getattr(self.language_detection, "disabled", False) is not True:
            if hasattr(self.language_detection, "languages") and isinstance(self.language_detection.languages, list) and self.language_detection.languages:
                for language in self.language_detection.languages:
                    detector_labels.append(f"language:{language}")
            else:
                detector_labels.append("language:any")
        if self.malicious_entity and getattr(self.malicious_entity, "disabled", False) is not True:
            detector_labels.append("malicious-entity")
        if self.pii_entity and getattr(self.pii_entity, "disabled", False) is not True:
            detector_labels.append("pii-entity")
        if self.prompt_injection and getattr(self.prompt_injection, "disabled", False) is not True:
            detector_labels.append("malicious-prompt")
        if self.secrets_detection and getattr(self.secrets_detection, "disabled", False) is not True:
            detector_labels.append("secrets")
        if self.topic and getattr(self.topic, "disabled", False) is not True:
            if hasattr(self.topic, "topics") and isinstance(self.topic.topics, list) and self.topic.topics:
                for topic_name in self.topic.topics:
                    detector_labels.append(f"topic:{topic_name}")
            else:
                detector_labels.append("topic:any")

        return detector_labels

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "Overrides":
        """
        Hydrate an Overrides instance from a raw dict.
        """
        if not data:
            return cls()
        return cls(
            ignore_recipe=data.get("ignore_recipe"),
            code_detection=(
                CodeDetection(**data["code_detection"])
                if isinstance(data.get("code_detection"), dict) else data.get("code_detection")
            ),
            competitors=(
                Competitors(**data["competitors"])
                if isinstance(data.get("competitors"), dict) else data.get("competitors")
            ),
            language_detection=(
                LanguageDetection(**data["language_detection"])
                if isinstance(data.get("language_detection"), dict) else data.get("language_detection")
            ),
            malicious_entity=(
                MaliciousEntity(**data["malicious_entity"])
                if isinstance(data.get("malicious_entity"), dict) else data.get("malicious_entity")
            ),
            pii_entity=(
                PIIEntity(**data["pii_entity"])
                if isinstance(data.get("pii_entity"), dict) else data.get("pii_entity")
            ),
            prompt_injection=(
                PromptInjection(**data["prompt_injection"])
                if isinstance(data.get("prompt_injection"), dict) else data.get("prompt_injection")
            ),
            secrets_detection=(
                SecretsDetection(**data["secrets_detection"])
                if isinstance(data.get("secrets_detection"), dict) else data.get("secrets_detection")
            ),
            topic=(
                Topic(**data["topic"])
                if isinstance(data.get("topic"), dict) else data.get("topic")
            ),
        )
