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
