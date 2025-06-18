# Copyright 2021 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import time
import json
import threading
from datetime import datetime
from typing import List, Dict
from utils.colors import DARK_RED, DARK_YELLOW, GREEN, RESET


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


def rate_limited(max_per_second):
    """
    Decorator to limit the rate of function calls.
    """
    min_interval = 1.0 / float(max_per_second)
    lock = threading.Lock()
    last_time_called = [0.0]

    def decorate(func):
        def rate_limited_function(*args, **kwargs):
            with lock:
                elapsed = time.perf_counter() - last_time_called[0]
                left_to_wait = min_interval - elapsed
                if left_to_wait > 0:
                    time.sleep(left_to_wait)
                last_time_called[0] = time.perf_counter()
                return func(*args, **kwargs)

        return rate_limited_function

    return decorate
