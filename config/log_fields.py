# Copyright 2021 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from dataclasses import dataclass
from typing import Optional


@dataclass
class LogFields:
    citations: Optional[str] = None
    extra_info: Optional[str] = None
    model: Optional[str] = None
    source: Optional[str] = None
    tools: Optional[str] = None
