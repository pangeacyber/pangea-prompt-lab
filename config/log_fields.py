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

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "LogFields":
        """
        Hydrate a LogFields instance from a raw dict.
        """
        if not data:
            return cls()
        return cls(
            citations=data.get("citations"),
            extra_info=data.get("extra_info"),
            model=data.get("model"),
            source=data.get("source"),
            tools=data.get("tools"),
        )
