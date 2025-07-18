#!/usr/bin/env -S poetry run python
# Copyright 2025 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from urllib.parse import urljoin

import os
import sys
import time
import requests
from requests.models import Response
import argparse
import json
import csv
from typing import List
from datetime import datetime
from tzlocal import get_localzone
from collections import Counter, defaultdict
from threading import Semaphore
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from dotenv import load_dotenv

load_dotenv(override=True)

# ANSI escape codes for colors
GREEN = "\033[92m"
BRIGHT_GREEN = "\033[1;92m"
DARK_GREEN = "\033[32m"

RED = "\033[91m"
BRIGHT_RED = "\033[1;91m"
DARK_RED = "\033[31m"

YELLOW = "\033[93m"
DARK_YELLOW = "\033[33m"

BLUE = "\033[94m"
DARK_BLUE = "\033[34m"

MAGENTA = "\033[95m"
CYAN = "\033[96m"

RESET = "\033[0m"

connection_timeout = 12
read_timeout = 60

prompt_guard_token = os.getenv("PANGEA_PROMPT_GUARD_TOKEN")
assert prompt_guard_token, "PANGEA_PROMPT_GUARD_TOKEN environment variable not set"

ai_guard_token = os.getenv("PANGEA_AI_GUARD_TOKEN")

base_url = os.getenv("PANGEA_BASE_URL")
assert base_url, "PANGEA_BASE_URL environment variable not set"

class Timer:
    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, *args):
        self.end = time.perf_counter()
        self.elapsed = self.end - self.start


class PromptDetection:
    def __init__(self, prompt, detector, labels=None):
        self.prompt = prompt
        self.detector = detector
        self.labels = labels


def create_error_response(status_code, message):
    """Create a mock error response."""
    response = Response()
    response.status_code = status_code
    error_content = {"status": status_code, "message": message}
    response._content = json.dumps(error_content).encode("utf-8")
    return response


def get_duration(response, verbose=False):
    try:
        if response is None:
            return 0
        response_json = response.json()
        if response_json is None:
            return 0
        request_time = response_json.get("request_time")
        response_time = response_json.get("response_time")
        if not request_time or not response_time:
            return 0
        request_time = datetime.fromisoformat(request_time.replace("Z", "+00:00"))
        response_time = datetime.fromisoformat(response_time.replace("Z", "+00:00"))
        duration = response_time - request_time
        return duration.total_seconds()
    except Exception as e:
        if verbose:
            print(f"\nError in get_duration response: {response}")
            e.errors = getattr(e, "errors", [])
            for err in e.errors:
                print(f"\t{err.detail} \n")
        return 0


def pangea_post_api(endpoint, data, token=prompt_guard_token):
    """Call Prompt Guard's public endpoint."""
    try:
        url = urljoin(base_url, endpoint)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        # print(f"pangea_post_api POST {url} with data: {json.dumps(data, indent=4)}")

        response = requests.post(url, headers=headers, json=data, timeout=(connection_timeout, read_timeout))
        if response is None:
            return create_error_response(500, "Internal server error: failed to fetch data")
        return response
    except requests.exceptions.Timeout:
        return create_error_response(408, "Request Timeout")
    except requests.exceptions.RequestException as e:
        return create_error_response(400, f"Bad Request: {e}")


def pangea_get_api(endpoint, token=prompt_guard_token):
    """GET request to the Prompt Guard public endpoint."""
    try:
        url = urljoin(base_url, endpoint)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        response = requests.get(url, headers=headers, timeout=(connection_timeout, read_timeout))
        return response
    except requests.exceptions.Timeout:
        return create_error_response(408, "Request Timeout")
    except requests.exceptions.RequestException as e:
        return create_error_response(400, f"Bad Request: {e}")


def pangea_request(request_id, token=prompt_guard_token):
    endpoint = f"/request/{request_id}"
    return pangea_get_api(endpoint, token=token)


def poll_request(request_id, max_attempts=10, verbose=False, token=prompt_guard_token):
    """Poll status until 'Success' or non-202 result, or max attempts reached."""
    status_code = "Accepted"
    counter = 1
    if verbose:
        print(f"\nPolling for response using URL: {base_url}/request/{request_id}")
    while status_code == "Accepted":
        response = pangea_request(request_id, token=token)
        if response is None:
            if verbose:
                print(f"\n{DARK_YELLOW}poll_request failed with no response.{RESET}")
            break
        status_code = response.json()["status"]
        if verbose:
            print(f" {DARK_BLUE}{counter}{RESET} : Polling status code is {status_code} ...", end="\r")
        if status_code == "Success":
            if verbose:
                print(f"\n{DARK_GREEN}Success{RESET} for request {request_id}:")
            break
        elif status_code != "Accepted":
            if verbose:
                print(f"\n{DARK_RED}Error{RESET} getting status: {status_code}")
                print("Full Response:")
                print(json.dumps(response.json(), indent=4))
            break

        if counter == max_attempts:
            if verbose:
                print(f"\n{RED}Max attempts reached. Exiting polling loop.{RESET}")
            break
        time.sleep(5)
        counter += 1
    return status_code, response


def print_response(prompt, response, result_only=False):
    """Utility to neatly print the API response."""
    try:
        if response is None:
            print(f"{DARK_YELLOW}Service failed with no response.{RESET}")
            return

        formatted_json_response = json.dumps(response.json(), indent=4)
        print(f"prompt: {prompt}")
        if response.status_code == 200:
            formatted_json_result = json.dumps(response.json()["result"], indent=4)
            if result_only:
                print(f"{formatted_json_result}\n")
            else:
                print(f"{formatted_json_response}\n")
        else:
            print(f"{DARK_YELLOW}Service failed with status code: {response.status_code}.{RESET}")
            print(f"{formatted_json_response}{RESET}")
    except Exception as e:
        print(f"\n{DARK_RED}Error in print_response: {e}\rPrompt was: {prompt}{RESET}")


def count_lines(filename):
    with open(filename, "r") as f:
        return sum(1 for _ in f)


def determine_injection(labels):
    """Heuristic to decide if this is injection or not based on labels."""
    benign_substrings = ["benign_auto", "benign"]
    benign_exact = ["conform"]

    for label in labels:
        if any(substring in label for substring in benign_substrings) or label in benign_exact:
            return False
    return True


def remove_outer_quotes(s: str) -> str:
    while len(s) > 1 and (
        (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'"))
    ):
        s = s[1:-1]
    return s


def rate_limited(max_per_second):
    """Decorator that limits the number of function calls per second."""
    min_interval = 1.0 / float(max_per_second)

    def decorator(func):
        last_time_called = [0.0]

        def rate_limited_function(*args, **kwargs):
            elapsed = time.time() - last_time_called[0]
            left_to_wait = min_interval - elapsed
            if left_to_wait > 0:
                time.sleep(left_to_wait)
            ret = func(*args, **kwargs)
            last_time_called[0] = time.time()
            return ret

        return rate_limited_function

    return decorator


class PromptDetectionManager:
    false_negatives: List[PromptDetection] = []
    false_positives: List[PromptDetection] = []

    def __init__(
        self,
        rps,
        report_file_name,
        args,
        prompt_guard_token=None,
        ai_guard_token=None,
        max_poll_attempts=10,
        verbose=False,
        report_title=None,
        summary_report_file=None,
        input_file=None,
        assume_tps=False,
        assume_tns=False,
        analyzers_list=None,
        use_ai_guard=False,
        topics=None,
        threshold=None,
        classify=False,
        classify_out_file=None
    ):
        self.args = args # Should switch to using this to make it easier to pass around
        self.rps = rps
        self.max_poll_attempts = max_poll_attempts
        self.verbose = verbose
        self.report_title = report_title
        self.summary_report_file = summary_report_file
        self.report_file_name = report_file_name
        self.input_file = input_file
        self.assume_tps = assume_tps
        self.assume_tns = assume_tns
        self.analyzers_list = analyzers_list
        self.use_ai_guard = use_ai_guard
        self.topics = topics
        self.threshold = threshold
        self.prompt_guard_token = prompt_guard_token
        self.ai_guard_token = ai_guard_token
        self.classify = classify
        self.classify_out_file = classify_out_file
        if self.classify:
            self._classify_lock = threading.Lock()
            if self.classify_out_file:
                open(self.classify_out_file, "w").close()

        self.tp_count = 0
        self.tn_count = 0
        self.fp_count = 0
        self.fn_count = 0
        self.duration_sum = 0.0
        self.total_calls = 0
        self.false_negatives = []
        self.false_positives = []
        self.fn_rate = 0.0
        self.fp_rate = 0.0
        self.errors = Counter()
        self.error_responses = []
        self.label_counts = Counter()
        self.label_stats = defaultdict(lambda: {"FP": 0, "FN": 0})

    def calculate_metrics(self):
        total = self.tp_count + self.fp_count + self.fn_count + self.tn_count
        accuracy = (self.tp_count + self.tn_count) / total if total else 0.0
        precision = self.tp_count / (self.tp_count + self.fp_count) if (self.tp_count + self.fp_count) else 0.0
        recall = self.tp_count / (self.tp_count + self.fn_count) if (self.tp_count + self.fn_count) else 0.0
        denom = recall + precision
        f1_score = (2 * (recall * precision) / denom) if denom > 0 else 0.0
        specificity = (
            self.tn_count / (self.tn_count + self.fp_count)
            if (self.tn_count + self.fp_count)
            else 0.0
        )
        fp_rate = (
            self.fp_count / (self.fp_count + self.tn_count)
            if (self.fp_count + self.tn_count)
            else 0.0
        )
        fn_rate = (
            self.fn_count / (self.tp_count + self.fn_count)
            if (self.tp_count + self.fn_count)
            else 0.0
        )
        avg_duration = self.duration_sum / self.total_calls if self.total_calls else 0.0
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "specificity": specificity,
            "fp_rate": fp_rate,
            "fn_rate": fn_rate,
            "avg_duration": avg_duration,
        }

    def add_error_response(self, response):
        self.errors[response.status_code] += 1
        self.error_responses.append(response)

    def add_tp(self):
        self.tp_count += 1

    def add_tn(self):
        self.tn_count += 1

    def add_fp(self):
        self.fp_count += 1

    def add_fn(self):
        self.fn_count += 1

    def add_duration(self, duration):
        self.duration_sum += duration

    def add_total_calls(self):
        self.total_calls += 1

    def add_false_negative(self, prompt, detector, labels):
        self.false_negatives.append(PromptDetection(prompt, detector, labels))

    def add_false_positive(self, prompt, detector, labels):
        self.false_positives.append(PromptDetection(prompt, detector, labels))

    def _write_classification(self, prompt, classifications):
        if not (self.classify and classifications):
            return
        with self._classify_lock:
            with open(self.classify_out_file, "a", encoding="utf-8") as jf:
                json.dump({"prompt": prompt, "classifications": classifications}, jf)
                jf.write("\n")

    def print_report_header(self):
        print(f"\n{BRIGHT_GREEN}Prompt Guard Efficacy Report{RESET}")
        if self.report_title:
            print(self.report_title)

        local_tz = get_localzone()
        local_time = datetime.now(local_tz)
        formatted_time = local_time.strftime("%Y-%m-%d %H:%M:%S %Z (UTC%z)")
        print(f"Report generated at: {formatted_time}")
        print(f"CMD: {' '.join(sys.argv)}")
        print(f"Input dataset: {self.report_file_name}")
        if self.use_ai_guard:
            print("Service: ai-guard")
        else:
            print("Service: prompt-guard")
        if self.analyzers_list:
            print(f"Analyzers: {self.analyzers_list}")
        else:
            print("Analyzers: Project Config")
        print(f"Total Calls: {self.total_calls}")
        print(f"Requests per second: {self.rps}")
        print(f"\n{RED}Errors: {self.errors}{RESET}")

        if self.summary_report_file:
            summary_report_csv = self.summary_report_file + ".csv"
            self.create_summary_csv(summary_report_csv)
            with open(self.summary_report_file, "w") as f:
                f.write("Prompt Guard Efficacy Report\n")
                if self.report_title:
                    f.write(f"{self.report_title}\n")
                f.write(f"Report generated at: {formatted_time}\n")
                f.write(f"Input dataset: {os.path.basename(self.report_file_name)}\n")
                f.write("Service: prompt-guard\n")
                f.write(f"CMD: {' '.join(sys.argv)}\n")
                f.write(f"Total Calls: {self.total_calls}\n")
                f.write(f"Requests per second: {self.rps}\n")
                f.write(f"Errors: {self.errors}\n")

    def print_errors(self):
        if len(self.errors) == 0:
            return
        if self.verbose:
            for error in self.error_responses:
                try:
                    formatted_json_error = json.dumps(error.json(), indent=4)
                    print(formatted_json_error)
                except Exception as e:
                    print(f"Error in print_errors: {e}")
                    print(f"Error response: {error}")
        if self.summary_report_file:
            error_report_file = self.summary_report_file + ".errors.txt"
            with open(error_report_file, "w") as f:
                f.write("\nErrors:\n")
                for error in self.error_responses:
                    try:
                        formatted_json_error = json.dumps(error.json(), indent=4)
                        f.write(f"{formatted_json_error}\n")
                    except Exception as e:
                        f.write(f"Error in print_errors: {e}\n")
                        f.write(f"Error response: {error}\n")

    def create_summary_csv(self, filename):
        headers = [
            "Date-Time",
            "Description",
            "CMD",
            "Input Dataset",
            "Service",
            "Analyzers",
            "Total Calls",
            "Requests per Second",
            "True Positives",
            "True Negatives",
            "False Positives",
            "False Negatives",
            "Accuracy",
            "Precision",
            "Recall",
            "F1 Score",
            "Specificity",
            "False Positive Rate",
            "False Negative Rate",
            "Average Duration",
            "ERRORS",
        ]

        data = {header: None for header in headers}
        local_tz = get_localzone()
        local_time = datetime.now(local_tz)
        formatted_time = local_time.strftime("%Y-%m-%d %H:%M:%S %Z (UTC%z)")

        data["Date-Time"] = formatted_time
        data["Description"] = self.report_title if self.report_title else None
        data["CMD"] = " ".join(sys.argv)
        data["Input Dataset"] = os.path.basename(self.input_file) if self.input_file else None
        data["Service"] = "prompt-guard"
        data["Analyzers"] = self.analyzers_list if self.analyzers_list else "Project Config"
        data["Total Calls"] = self.total_calls
        data["Requests per Second"] = self.rps
        data["True Positives"] = self.tp_count
        data["True Negatives"] = self.tn_count
        data["False Positives"] = self.fp_count
        data["False Negatives"] = self.fn_count

        metrics = self.calculate_metrics()
        data["Accuracy"] = metrics["accuracy"]
        data["Precision"] = metrics["precision"]
        data["Recall"] = metrics["recall"]
        data["F1 Score"] = metrics["f1_score"]
        data["Specificity"] = metrics["specificity"]
        data["False Positive Rate"] = metrics["fp_rate"]
        data["False Negative Rate"] = metrics["fn_rate"]
        data["Average Duration"] = metrics["avg_duration"]
        data["ERRORS"] = self.errors

        with open(filename, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            writer.writerow(data)

    def print_stats(self):
        print(f"\n{DARK_GREEN}True Positives: {self.tp_count}{RESET}")
        print(f"{DARK_GREEN}True Negatives: {self.tn_count}{RESET}")
        print(f"{DARK_RED}False Positives: {self.fp_count}{RESET}")
        print(f"{DARK_RED}False Negatives: {self.fn_count}{RESET}")

        metrics = self.calculate_metrics()
        print(f"\nAccuracy: {DARK_GREEN}{metrics['accuracy']:.4f}{RESET}")
        print(f"Precision: {DARK_GREEN}{metrics['precision']:.4f}{RESET}")
        print(f"Recall: {DARK_GREEN}{metrics['recall']:.4f}{RESET}")
        print(f"F1 Score: {DARK_GREEN}{metrics['f1_score']:.4f}{RESET}")
        print(f"Specificity: {DARK_GREEN}{metrics['specificity']:.4f}{RESET}")
        print(f"False Positive Rate: {DARK_RED}{metrics['fp_rate']:.4f}{RESET}")
        print(f"False Negative Rate: {DARK_RED}{metrics['fn_rate']:.4f}{RESET}")
        if self.total_calls > 0:
            avg_duration = self.duration_sum / self.total_calls
            print(f"Average duration: {avg_duration:.4f} seconds")

        if self.summary_report_file:
            with open(self.summary_report_file, "a") as f:
                f.write(f"\nTrue Positives: {self.tp_count}\n")
                f.write(f"True Negatives: {self.tn_count}\n")
                f.write(f"False Positives: {self.fp_count}\n")
                f.write(f"False Negatives: {self.fn_count}\n")
                f.write(f"\nAccuracy: {metrics['accuracy']:.4f}\n")
                f.write(f"Precision: {metrics['precision']:.4f}\n")
                f.write(f"Recall: {metrics['recall']:.4f}\n")
                f.write(f"F1 Score: {metrics['f1_score']:.4f}\n")
                f.write(f"Specificity: {metrics['specificity']:.4f}\n")
                f.write(f"False Positive Rate: {metrics['fp_rate']:.4f}\n")
                f.write(f"False Negative Rate: {metrics['fn_rate']:.4f}\n")
                if self.total_calls > 0:
                    f.write(f"Average duration: {metrics['avg_duration']:.4f} seconds\n")
                f.write("\nLabel counts:\n")
                for label, count in self.label_counts.items():
                    f.write(f"{label}: {count}\n")

    def print_label_stats(self):
        print("\nLabel-wise False Positives and False Negatives:")
        for label, stats in self.label_stats.items():
            fp = stats.get("FP", 0)
            fn = stats.get("FN", 0)
            print(f"Label: {label}, False Positives: {fp}, False Negatives: {fn}")

    def process_response(self, prompt, response, is_injection, labels):
        for label in labels:
            self.label_counts[label] += 1
        self._process_prompt_guard_response(prompt, response, is_injection, labels)

    def get_ai_guard_detected_details(self, response):
        detected = False
        detectors = []  # List of detectors that detected something
        detected_with_details = defaultdict(list)

        try:
            if response is None:
                print(f"{DARK_YELLOW}Service failed with no response.{RESET}")
                return detected, detectors, detected_with_details

            if response.status_code != 200:
                if self.verbose:
                    print(f"Error in check_result: {response.status_code}")
                return detected, detectors, detected_with_details

            # Safely parse JSON, handle possible exceptions
            try:
                resp_json = response.json()
            except Exception as e:
                print(f"{DARK_RED}Failed to parse response JSON: {e}{RESET}")
                return detected, detectors, detected_with_details

            if (
                isinstance(resp_json, dict)
                and "result" in resp_json
                and "detectors" in resp_json["result"]
            ):
                for detector, details in resp_json["result"]["detectors"].items():
                    if details.get("detected", False):
                        detected = True
                        detectors.append(detector)
                        # Handle prompt_injection separately to extract analyzer and confidence
                        if detector == "prompt_injection":
                            for analyzer_response in details["data"].get(
                                "analyzer_responses", []
                            ):
                                analyzer = analyzer_response.get(
                                    "analyzer", "Unknown"
                                )
                                confidence = analyzer_response.get(
                                    "confidence", "Unknown"
                                )
                                detected_with_details[detector].append(
                                    f"analyzer: {analyzer}, confidence: {confidence}"
                                )
                                detectors.append(analyzer)
                        elif detector == "malicious_entity":
                            entities = details["data"].get("entities", [])
                            for entity in entities:
                                entity_str = (
                                    f"{entity['type']}: {entity['value']}"
                                )
                                if "action" in entity:
                                    entity_str += (
                                        f" (action: {entity['action']})"
                                    )
                                detected_with_details[detector].append(
                                    entity_str
                                )
                                detectors.append(entity["type"])
                        elif detector == "topic":
                            topics = details["data"].get("topics", [])
                            for topic in topics:
                                topic_name = topic.get("topic")
                                if topic_name:
                                    detected_with_details[detector].append(
                                        topic_name
                                    )
                                    detectors.append(topic_name)
                        elif detector == "language_detection":
                            language = details["data"].get("language")
                            if language:
                                detected_with_details[detector].append(
                                    language
                                )
                                detectors.append(language)
                        elif detector == "code_detection":
                            language = details["data"].get("language")
                            if language:
                                detected_with_details[detector].append(
                                    language
                                )
                                detectors.append(language)
                        else:
                            # For other detectors, just append the data as a string
                            detected_with_details[detector].append(
                                str(details["data"])
                            )
                            detectors.append(str(details["data"]))
            else:
                if self.verbose:
                    print(
                        "Unexpected response format: "
                        f"{json.dumps(resp_json, indent=4)}"
                    )
        except Exception as e:
            if self.verbose:
                print(f"Error in get_ai_guard_detected_details: {e}")
                try:
                    print(
                        f"Response: {json.dumps(response.json(), indent=4)}"
                    )
                except Exception:
                    print(f"Response: {response}")

        return detected, detectors, detected_with_details

    def _process_prompt_guard_response(self, prompt, response, is_injection, labels):
        if response.status_code != 200:
            if self.verbose:
                print(f"Error in check_result: {response.status_code}")
            return

        detected = False
        detectors = []
        detected_with_details = defaultdict(list)
        result = response.json().get("result", {})

        # record classification
        self._write_classification(prompt, result.get("classifications"))

        if self.use_ai_guard:
            detected, detectors, detected_with_details = self.get_ai_guard_detected_details(response)
            if not detected:
                detectors = ["None"]
            else:
                temp_detectors = []
                for detector, details in detected_with_details.items():
                    if isinstance(details, list):
                        details_str = ", ".join(details)
                    else:
                        details_str = str(details)
                    temp_detectors.append(f"{detector}: {details_str}")
                if len(temp_detectors) == 0:
                    temp_detectors = ["None"]
                detectors = temp_detectors
        else:
            detected = result.get("detected", False)
            detectors.append(result.get("analyzer", "None"))

        if is_injection:
            if detected:
                self.add_tp()
            else:
                self.add_fn()
                for detector in detectors:
                    self.add_false_negative(prompt, detector, labels)
                if self.verbose:
                    print(f"\n{DARK_RED}FALSE NEGATIVE: prompt: {prompt}")
                    print(f"{json.dumps(result, indent=4)}\n{RESET}")
                for label in labels:
                    self.label_stats[label]["FN"] += 1
        else:
            if detected:
                self.add_fp()
                for detector in detectors:
                    self.add_false_positive(prompt, detector, labels)
                if self.verbose:
                    print(f"\n{DARK_YELLOW}FALSE POSITIVE: {prompt}")
                    print(f"{json.dumps(result, indent=4)}\n{RESET}")
                for label in labels:
                    self.label_stats[label]["FP"] += 1
            else:
                self.add_tn()


    def prompt_guard_analyzers(self):
        """Fetch a list of detector names from the Prompt Guard service."""
        endpoint = "/v1/detector/list"
        data = {}
        response = pangea_post_api(endpoint, data)
        try:
            if response.status_code != 200:
                print(f"Error fetching analyzers: {response.status_code}")
                print(json.dumps(response.json(), indent=4))
                return []
            resp_json = response.json()
            analyzers_data = resp_json.get("result", {}).get("analyzers")
            if not isinstance(analyzers_data, list):
                print("Unexpected format in response: 'analyzers' missing or not a list.")
                return []
            analyzers = [analyzer.get("name", "<missing name>") for analyzer in analyzers_data]
            print(f"Fetched {len(analyzers)} analyzers: {analyzers}")
            return analyzers
        except Exception as e:
            print(f"Exception while fetching analyzers: {e}")
            return []

    def prompt_guard_service(self, messages):
        """Submit a single prompt to the Prompt Guard service using the full messages array."""
        endpoint = "/v1/guard"

        data = {"messages": messages}

        if self.analyzers_list:
            data["analyzers"] = self.analyzers_list

        if self.classify:
            data["classify"] = True

        response = pangea_post_api(endpoint, data)
        if response.status_code == 202:
            request_id = response.json()["request_id"]
            _, response = poll_request(request_id, max_attempts=self.max_poll_attempts, verbose=self.verbose)

        duration = get_duration(response, verbose=self.verbose)
        if duration > 0:
            self.add_total_calls()
            self.add_duration(duration)

        if response.status_code != 200:
            self.add_error_response(response)
        return response

    def ai_guard_service(
            self,
            messages,
            topics=None,
            threshold=None
            ):
        """
        Submit a single prompt to the AI Guard service using the full messages array.
        The recipe can be specified, defaulting to "pangea_prompt_guard".
        """
        endpoint = "/v1/text/guard"

        if not topics:
            if self.topics:
                topics = self.topics
            else:
                topics=[
                    "toxicity",
                    "self harm and violence",
                    "roleplay",
                    "weapons",
                    "criminal-conduct",
                    "sexual"
                ]
        # Topics have to be lowercased:
        topics = [topic.lower() for topic in topics]
        if not threshold:
            if self.threshold:
                threshold = self.threshold
            else:
                threshold=1.0

        overrides = {
            "ignore_recipe": True,
            "prompt_injection": {
                "disabled": False,
                "action": "block"
            },
            "topic": {
                "disabled": False,
                "action": "block",
                "threshold": threshold,
                "topics": topics
            }
        }
        data = {
            "recipe": "pangea_prompt_guard",
            "messages": messages,
            "overrides": overrides,
            "debug": self.verbose,
        }

        # if self.verbose:
        #     print(f"\n{DARK_BLUE}Sending AI Guard request with data: {json.dumps(data, indent=4)}{RESET}")

        response = pangea_post_api(endpoint, data, self.ai_guard_token)
        if response.status_code == 202:
            print(f"\n{DARK_BLUE}Polling for AI Guard response...{RESET}")
            request_id = response.json()["request_id"]
            _, response = poll_request(request_id, max_attempts=self.max_poll_attempts, verbose=self.verbose, token=self.ai_guard_token)

        duration = get_duration(response, verbose=self.verbose)
        if duration > 0:
            self.add_total_calls()
            self.add_duration(duration)

        if response.status_code != 200:
            self.add_error_response(response)
        return response

def output_final_reports(args, pg, fns_out_csv, fps_out_csv):
    if args.print_fps and len(pg.false_positives) > 0:
        print("\nFalse Positives:")
        print("prompt", "detector")
        for detection in pg.false_positives:
            print(f'"{detection.prompt}", "{detection.detector}"')

    if args.print_fns and len(pg.false_negatives) > 0:
        print("\nFalse Negatives:")
        for detection in pg.false_negatives:
            print(f'"{detection.prompt}"')

    pg.print_report_header()
    pg.print_errors()
    pg.print_stats()

    if args.print_label_stats:
        pg.print_label_stats()

    if args.print_fps and len(pg.false_positives) > 0:
        print("\nFalse Positives:")
        print("prompt", "detector")
        for detection in pg.false_positives:
            print(f'"{detection.prompt}", "{detection.detector}"')

    if args.print_fns and len(pg.false_negatives) > 0:
        print("\nFalse Negatives:")
        for detection in pg.false_negatives:
            print(f'"{detection.prompt}"')

    if args.fps_out_csv and len(pg.false_positives) > 0:
        print(f"Writing false positives to {fps_out_csv}")
        with open(fps_out_csv, mode="w", newline="", encoding="utf-8") as csvfile:
            csvwriter = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
            csvwriter.writerow(["prompt", "detector", "labels"])
            for detection in pg.false_positives:
                csvwriter.writerow([detection.prompt, detection.detector, ",".join(detection.labels)])

    if args.fns_out_csv and len(pg.false_negatives) > 0:
        print(f"Writing false negatives to {fns_out_csv}")
        with open(fns_out_csv, mode="w", newline="", encoding="utf-8") as csvfile:
            csvwriter = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
            csvwriter.writerow(["prompt", "detector", "labels"])
            for detection in pg.false_negatives:
                csvwriter.writerow([detection.prompt, detection.detector, ",".join(detection.labels)])


def process_all_prompts(args, pg):
    max_workers = int(args.rps) if args.rps >= 1 else 1
    semaphore = Semaphore(max_workers)

    @rate_limited(args.rps)
    def process_prompt(messages, is_injection, labels, index, total_rows):
        with semaphore:
            progress = (index + 1) / total_rows * 100
            print("\r\033[2K", end="")
            print(f"{progress:.2f}%", end="\r", flush=True)
            if pg.use_ai_guard:
                response = pg.ai_guard_service(messages)
            else:
                response = pg.prompt_guard_service(messages)
            # Use the first user message (if available) for logging
            prompt_text = next((msg["content"] for msg in messages if msg["role"] == "user"), "No User Message")
            if response.status_code != 200 and pg.verbose:
                print_response(prompt_text, response)
            else:
                pg.process_response(prompt_text, response, is_injection, labels)

    fns_out_csv = args.fns_out_csv
    fps_out_csv = args.fps_out_csv

    # Single prompt
    if args.prompt:
        if args.use_ai_guard:
            response = pg.ai_guard_service([{"role": "user", "content": args.prompt}])
        else:
            response = pg.prompt_guard_service([{"role": "user", "content": args.prompt}])
        print_response(args.prompt, response, True)
        return

    # Otherwise, read from file
    input_file = args.input_file
    file_extension = os.path.splitext(input_file)[1].lower()

    if file_extension == ".json":
        with open(input_file, "r") as file:
            data = json.load(file)
            test_cases = []
            if isinstance(data, dict) and "tests" in data:
                for test_case in data["tests"]:
                    # Retrieve the messages array as-is
                    messages = test_case.get("messages", [])
                    labels = test_case.get("label", [])
                    test_cases.append((messages, labels))
            elif isinstance(data, list):
                # For old format: convert each item into a messages array.
                for item in data:
                    messages = []
                    if "user" in item:
                        messages.append({"role": "user", "content": item["user"]})
                    if "system" in item:
                        messages.append({"role": "system", "content": item["system"]})
                    if "assistant" in item and item["assistant"]:
                        messages.append({"role": "assistant", "content": item["assistant"]})
                    labels = item.get("label", [])
                    test_cases.append((messages, labels))
            else:
                print("Error: JSON file format is not recognized.")
                return

            total_rows = len(test_cases)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                for index, (messages, labels) in enumerate(test_cases):
                    is_injection = determine_injection(labels)
                    futures.append(executor.submit(process_prompt, messages, is_injection, labels, index, total_rows))
                for future in as_completed(futures):
                    pass

    elif file_extension == ".jsonl":
        # --------------------------------------------------------------
        # JSON Lines input: one JSON object per line
        # --------------------------------------------------------------
        test_cases = []
        with open(input_file, "r", encoding="utf-8") as file:
            for i, line in enumerate(file, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except Exception:
                    print(f"Skipping invalid JSON line {i}: {line}")
                    continue
                messages = data.get("messages", [])
                labels = data.get("label", [])
                test_cases.append((messages, labels))
        print(f"Loaded {len(test_cases)} test cases from input file.")

        total_rows = len(test_cases)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for index, (messages, labels) in enumerate(test_cases):
                is_injection = determine_injection(labels)
                futures.append(
                    executor.submit(
                        process_prompt,
                        messages,
                        is_injection,
                        labels,
                        index,
                        total_rows,
                    )
                )
            for future in as_completed(futures):
                pass

    elif file_extension == ".txt":
        # --------------------------------------------------------------
        # Plain‑text input: one prompt per line
        # --------------------------------------------------------------
        total_rows = count_lines(input_file)

        # Decide the default injection assumption.
        if args.assume_tps:
            default_injection = True
        elif args.assume_tns:
            default_injection = False
        else:
            default_injection = False

        with open(input_file, "r", encoding="utf-8") as file, ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            idx = 0
            for raw_line in file:
                prompt = raw_line.strip()
                if not prompt:
                    continue
                futures.append(
                    executor.submit(
                        process_prompt,
                        [{"role": "user", "content": prompt}],  # messages array
                        default_injection,  # is_injection
                        [],                 # labels
                        idx,
                        total_rows,
                    )
                )
                idx += 1
            for future in as_completed(futures):
                pass

    elif file_extension == ".csv":
        with open(input_file, mode="r", newline="", encoding="utf-8") as csvfile:
            total_rows = sum(1 for _ in csv.reader(csvfile)) - 1

        with open(input_file, mode="r", newline="", encoding="utf-8") as csvfile:
            csvreader = csv.DictReader(csvfile, quoting=csv.QUOTE_MINIMAL)
            normalized_fieldnames = {
                field.strip('"').lower(): field.strip('"') for field in csvreader.fieldnames
            }
            prompt_field = normalized_fieldnames.get("user prompt")
            injection_field = normalized_fieldnames.get("prompt injection")
            if not prompt_field or not injection_field:
                print(f"Error: Required columns not found. Available: {list(normalized_fieldnames.keys())}")
                return

            prompts = []
            for row in csvreader:
                text = json.dumps(
                    row[normalized_fieldnames["user prompt"]].replace("\n", " ").replace("\r", " ")
                )
                text = remove_outer_quotes(text)
                inj = row[normalized_fieldnames["prompt injection"]] == "1"
                prompts.append((text, inj, []))

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                for index, (prompt, is_injection, _) in enumerate(prompts):
                    futures.append(executor.submit(
                        process_prompt,
                        [{"role": "user", "content": prompt}],  # messages array
                        is_injection,
                        [],     # labels
                        index,
                        total_rows))
                for future in as_completed(futures):
                    pass

    else:
        # Assume text file with one prompt per line.
        if not (args.assume_tps or args.assume_tns):
            print("Error: Must specify --assume_tps or --assume_tns for text file input")
            return

        is_injection = args.assume_tps
        total_rows = count_lines(input_file)
        with open(input_file, "r") as file:
            prompt_lines = [(line.strip(), is_injection, []) for line in file if line.strip()]

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for index, (prompt, inj, labels) in enumerate(prompt_lines):
                futures.append(executor.submit(process_prompt, prompt, inj, labels, index, total_rows))
            for future in as_completed(futures):
                pass

    output_final_reports(args, pg, fns_out_csv, fps_out_csv)


def main():
    global base_url
    start_time = time.time()

    parser = argparse.ArgumentParser(
        description=(
            "Process a prompt with Prompt Guard API or read prompts from "
            "a txt (one per line), JSON (tps/tns), or CSV (SPML format)."
        )
    )

    group = parser.add_mutually_exclusive_group(required=True)

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output (FPs, FNs as they occur, full errors).",
    )
    parser.add_argument("--report_title", type=str, default=None, help="Optional title in report summary")
    parser.add_argument("--summary_report_file", type=str, default=None, help="Optional summary report file name")

    group.add_argument("--prompt", type=str, help="A single prompt string to process")
    group.add_argument(
        "--input_file",
        type=str,
        help="File containing prompts: .txt, .json (tps/tns), or .csv (SPML format).",
    )
    group.add_argument(
        "--list_analyzers",
        action="store_true",
        help="List available analyzers for the Prompt Guard service and exit",
    )

    parser.add_argument(
        "--analyzers",
        type=str,
        help="Comma-separated analyzers (e.g. PA2001,PA2002)",
    )

    parser.add_argument(
        "--fp_check_only",
        action="store_true",
        help="When passing JSON with tps/tns, only check for false negatives",
    )

    group_tp_tn = parser.add_mutually_exclusive_group(required=False)
    group_tp_tn.add_argument(
        "--assume_tps",
        action="store_true",
        help="Assume all prompts in a .txt file are true positives",
    )
    group_tp_tn.add_argument(
        "--assume_tns",
        action="store_true",
        help="Assume all prompts in a .txt file are true negatives",
    )

    parser.add_argument("--fps_out_csv", type=str, help="Output CSV for false positives")
    parser.add_argument("--fns_out_csv", type=str, help="Output CSV for false negatives")
    parser.add_argument("--print_fps", action="store_true", help="Print false positives at the end")
    parser.add_argument("--print_fns", action="store_true", help="Print false negatives at the end")
    parser.add_argument("--rps", type=float, default=1.0, help="Requests per second")
    parser.add_argument(
        "--max_poll_attempts",
        type=int,
        default=10,
        help="Max poll attempts for 202 responses (default: 10)",
    )
    parser.add_argument(
        "--print_label_stats",
        action="store_true",
        help="Display per-label stats (FP/FN counts)",
    )

    parser.add_argument(
        "--use_ai_guard",
        action="store_true",
        help=(
            "Use AI Guard service instead of Prompt Guard. "
            "This will use the AI Guard API with a forced recipe of malicious prompt and topic detectors with default topics: "
            "toxicity, self harm and violence, roleplay, weapons, criminal-conduct, sexual."
        ),
    )
    parser.add_argument(
        "--topics",
        type=str,
        default="toxicity,self harm and violence,roleplay,weapons,criminal-conduct,sexual",
        help=(
            "Comma-separated list of topics to use with AI Guard. "
            "Available topics: "
            "'toxicity, self harm and violence, roleplay, weapons, criminal-conduct, sexual, financial-advice, legal-advice, religion, politics, health-coverage, negative-sentiment, gibberish'.  "
            "Default: 'toxicity,self harm and violence,roleplay,weapons,criminal-conduct,sexual'"
        ),
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=1.0,
        help=(
            "Threshold for topic detection confidence. "
            "Only applies when using AI Guard with topics. Default: 1.0"
        ),
    )
    parser.add_argument("--classify", action="store_true",
                        help="Enable classify=true and write JSONL output.")
    parser.add_argument("--classify_out_jsonl", type=str, default=None,
                        help="Path for classification JSONL output file.")

    args = parser.parse_args()

    if args.classify and not args.classify_out_jsonl:
        if args.input_file:
            base_name = os.path.splitext(os.path.basename(args.input_file))[0]
            args.classify_out_jsonl = f"{base_name}.classifications.jsonl"
        else:
            args.classify_out_jsonl = "classifications_output.jsonl"
        print(f"[INFO] Classification results will be written to: {args.classify_out_jsonl}")

    # If listing analyzers, just fetch and exit
    if args.list_analyzers:
        temp_pg = PromptDetectionManager(
            args=args,
            rps=1.0,
            report_file_name="",
            max_poll_attempts=10,
        )
        temp_pg.prompt_guard_analyzers()
        return

    analyzers_list = args.analyzers.split(",") if args.analyzers else None

    if args.use_ai_guard:
        if ai_guard_token is None:
            print(
                f"{DARK_RED}Error: --use_ai_guard requires the AI Guard token to be set in the environment variable PANGAEA_AI_GUARD_TOKEN.{RESET}"
            )
            return
        # Need to modify base_url to use AI Guard.
        # If base_url contains "prompt-guard", replace it with "ai-guard".
        if base_url and "prompt-guard" in base_url:
            base_url = base_url.replace("prompt-guard", "ai-guard")
            # print(f"Using AI Guard base URL: {base_url}")
        else:
            if base_url and "ai-guard" not in base_url:
                print(
                    f"{DARK_RED}Warning: --use_ai_guard is set, but base_url does not contain 'ai-guard'. "
                    "Ensure you are using the correct AI Guard endpoint.{RESET}"
                )

        if analyzers_list:
            print(
                f"{DARK_RED}Warning: --analyzers is ignored when using --use_ai_guard. "
                "AI Guard uses its own set of topics and analyzers.{RESET}"
            )
            analyzers_list = None

    topics = (
        [t.strip().lower() for t in args.topics.split(",")] if args.use_ai_guard and args.topics else None
    )  # Use provided topics or default if not specified
    if args.use_ai_guard and not topics:
        topics = [
            "toxicity",
            "self harm and violence",
            "roleplay",
            "weapons",
            "criminal-conduct",
            "sexual"
        ]

    pg = PromptDetectionManager(
        prompt_guard_token=prompt_guard_token,
        ai_guard_token=ai_guard_token,
        args=args,
        rps=args.rps,
        report_file_name=args.input_file,
        max_poll_attempts=args.max_poll_attempts,
        verbose=args.verbose,
        report_title=args.report_title,
        summary_report_file=args.summary_report_file,
        input_file=args.input_file,
        assume_tps=args.assume_tps,
        assume_tns=args.assume_tns,
        analyzers_list=analyzers_list,
        use_ai_guard=args.use_ai_guard,
        topics=topics,
        threshold=args.threshold,
        classify=args.classify,
        classify_out_file=args.classify_out_jsonl
    )

    process_all_prompts(args, pg)

    end_time = time.time()
    print(f"\nTotal duration: {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
