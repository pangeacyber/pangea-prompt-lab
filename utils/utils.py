# Copyright 2021 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import time
import json
import threading
from collections import deque
from datetime import datetime
from typing import List, Dict
from utils.colors import DARK_RED, DARK_YELLOW, GREEN, RESET
from defaults import defaults


def remove_topic_prefix(labels: list[str]) -> list[str]:
    """
    Remove the 'topic:' prefix from a list of labels.
    If a label starts with 'topic:', it will be stripped of that prefix.
    """
    return [label[len(defaults.topic_prefix):] if label.startswith(defaults.topic_prefix) else label for label in labels]

# Helper function to normalize topics and detectors
def normalize_topics_and_detectors(
    labels: list[str],
    valid_detectors: list[str],
    valid_topics: list[str],
) -> tuple[list[str], list[str]]:
    """
    Normalize a list of label strings:
      - Valid topics (with/without 'topic:' prefix) become 'topic:<name>'
      - Valid detector names are left as-is
      - Duplicates removed, order preserved
      - If "topic" is there by itself, just remove it (TODO: Or just add all topics?).
      - Returns (normalized_list, invalid_list)
    """
    seen = set()
    normalized = []
    invalid = []

    valid_detectors_set = set(valid_detectors)
    valid_topics_set = set(valid_topics)

    for label in labels:
        lbl = label.strip().lower()
        # Topic with prefix
        if lbl.startswith(defaults.topic_prefix):
            prefix_len = len(defaults.topic_prefix)
            topic_name = lbl[prefix_len:]
            if topic_name in valid_topics_set:
                norm = f"{defaults.topic_prefix}{topic_name}"
                if norm not in seen:
                    normalized.append(norm)
                    seen.add(norm)
            else:
                invalid.append(label)
        # Raw topic name
        elif lbl in valid_topics_set:
            norm = f"{defaults.topic_prefix}{lbl}"
            if norm not in seen:
                normalized.append(norm)
                seen.add(norm)
        # Detector name
        elif lbl in valid_detectors_set:
            if lbl not in seen:
                normalized.append(lbl)
                seen.add(lbl)
        else:
            invalid.append(label)

    return normalized, invalid


def apply_synonyms(labels, synonyms, replacement):
    """
    Replace any label in labels that matches a synonym in synonyms with the specified replacement.
    Remove duplicates from the resulting list.
    """
    if isinstance(labels, str):
        labels = [labels]

    return list(set(
        replacement if label in synonyms else label
        for label in labels
        if isinstance(label, str)
    ))


def formatted_json_str(json_data: dict) -> str:
    return json.dumps(json_data, indent=4)


def get_duration(response, verbose=False):
    try:
        if response is None:
            return 0
        response_json = response.json()
        if response_json is None:
            return 0
        request_time = response_json.get("request_time", None)
        response_time = response_json.get("response_time", None)
        if request_time is None or response_time is None:
            return 0
        request_time = datetime.fromisoformat(request_time.replace("Z", "+00:00"))
        response_time = datetime.fromisoformat(response_time.replace("Z", "+00:00"))
        duration = response_time - request_time
        return duration.total_seconds()
    except Exception as e:
        if verbose:
            print(f"\nError in get_duration response: {response}")
            errors = getattr(e, "errors", [])
            for err in errors:
                print(f"\t{err.detail} \n")
        return 0


def print_response(messages: List[Dict[str, str]], response, result_only=False):
    """Utility to neatly print the API response."""
    try:
        if response is None:
            print(f"{DARK_YELLOW}Service failed with no response.{RESET}")
            return

        formatted_json_response = formatted_json_str(response.json())

        print(f"messages: {messages[:1]}")
        if response.status_code == 200:
            formatted_json_result = formatted_json_str(response.json().get("result"))

            if result_only:
                print(f"{formatted_json_result}\n")
            else:
                print(f"{formatted_json_response}\n")
        else:
            # Handle error
            print(f"{DARK_YELLOW}Service failed with status code: {response.status_code}.{RESET}")
            print(f"{formatted_json_response}{RESET}")
    except Exception as e:
        print(f"\n{DARK_RED}Error in print_response: {e}\nmessages was: {messages}{RESET}")


def remove_outer_quotes(s: str) -> str:
    # Keep removing a layer of quotes as long as the first and last characters are the same quote type.
    while len(s) > 1 and ((s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'"))):
        s = s[1:-1]
    return s


def unescape_and_unquote(value):
    """
    Handles strings with multiple layers of quoting and escape sequences:
    1. Unescapes escape sequences (e.g., \\" to ").
    2. Removes all surrounding quotes recursively.
    """
    # Unescape escaped sequences (e.g., \\" -> ", \\' -> ', \\\\ -> \)
    value = value.replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")

    # Strip all surrounding quotes recursively
    while (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        value = value[1:-1]

    return value


# Shared state: one bucket per requested RPS value
_RATE_LIMITER_STATE: dict[float, dict[str, object]] = {}

def rate_limited(max_per_second: float):
    """
    Thread‑safe decorator that enforces a *global* requests‑per‑second cap.

    Any function wrapped with the same ``max_per_second`` value shares a
    single token bucket across every thread and module.

    Example
    -------
    @rate_limited(10)      # <= 10 calls per second in total
    def api_call(...):
        ...
    """
    if max_per_second <= 0:
        return lambda f: f  # no limit requested

    window = 1.0  # sliding window in seconds
    state = _RATE_LIMITER_STATE.setdefault(
        max_per_second,
        {"lock": threading.Lock(), "calls": deque()}
    )
    lock: threading.Lock = state["lock"]
    call_times: deque = state["calls"]

    def decorator(fn):
        import functools
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            while True:
                with lock:
                    now = time.perf_counter()
                    # Drop timestamps older than the window
                    while call_times and now - call_times[0] >= window:
                        call_times.popleft()

                    if len(call_times) < max_per_second:
                        call_times.append(now)
                        break
                    sleep_for = window - (now - call_times[0])
                if sleep_for > 0:
                    time.sleep(sleep_for)
            return fn(*args, **kwargs)
        return wrapper
    return decorator
