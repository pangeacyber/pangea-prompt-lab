#!/usr/bin/env -S poetry run python
# Copyright 2025 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import os
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

connection_timeout = 10
read_timeout = 60

token = os.getenv("PANGEA_PROMPT_GUARD_TOKEN")
assert token, "PANGEA_PROMPT_GUARD_TOKEN environment variable not set"
domain = os.getenv("PANGEA_DOMAIN")
assert domain, "PANGEA_DOMAIN environment variable not set"


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


def pangea_post_api(endpoint, data):
    """Call Prompt Guard's public endpoint."""
    try:
        base_url = f"https://prompt-guard.{domain}"

        url = f"{base_url}{endpoint}"

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        response = requests.post(url, headers=headers, json=data, timeout=(connection_timeout, read_timeout))
        if response is None:
            return create_error_response(500, "Internal server error: failed to fetch data")
        return response
    except requests.exceptions.Timeout:
        return create_error_response(408, "Request Timeout")
    except requests.exceptions.RequestException as e:
        return create_error_response(400, f"Bad Request: {e}")


def pangea_get_api(endpoint):
    """GET request to the Prompt Guard public endpoint."""
    try:
        base_url = f"https://prompt-guard.{domain}"
        url = f"{base_url}{endpoint}"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        response = requests.get(url, headers=headers, timeout=(connection_timeout, read_timeout))
        return response
    except requests.exceptions.Timeout:
        return create_error_response(408, "Request Timeout")
    except requests.exceptions.RequestException as e:
        return create_error_response(400, f"Bad Request: {e}")


def pangea_request(request_id):
    endpoint = f"/request/{request_id}"
    return pangea_get_api(endpoint)


def poll_request(request_id, max_attempts=10, verbose=False):
    """Poll status until 'Success' or non-202 result, or max attempts reached."""
    status_code = "Accepted"
    counter = 1
    if verbose:
        print(f"\nPolling for response using URL: https://prompt-guard.pangea.cloud/request/{request_id}")
    while status_code == "Accepted":
        response = pangea_request(request_id)
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
    benign_labels = {"benign_auto", "benign"}
    return not any(label in benign_labels for label in labels)


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
        max_poll_attempts=10,
        verbose=False,
        report_title=None,
        summary_report_file=None,
        input_file=None,
        assume_tps=False,
        assume_tns=False,
        analyzers_list=None,
    ):
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

    def print_report_header(self):
        print(f"\n{BRIGHT_GREEN}Prompt Guard Efficacy Report{RESET}")
        if self.report_title:
            print(self.report_title)

        local_tz = get_localzone()
        local_time = datetime.now(local_tz)
        formatted_time = local_time.strftime("%Y-%m-%d %H:%M:%S %Z (UTC%z)")
        print(f"Report generated at: {formatted_time}")
        print(f"Input dataset: {self.report_file_name}")
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

    def _process_prompt_guard_response(self, prompt, response, is_injection, labels):
        if response.status_code != 200:
            if self.verbose:
                print(f"Error in check_result: {response.status_code}")
            return

        result = response.json().get("result", {})
        detected = result.get("detected", False)
        detector = result.get("analyzer", "None")

        if is_injection:
            if detected:
                self.add_tp()
            else:
                self.add_fn()
                self.add_false_negative(prompt, detector, labels)
                if self.verbose:
                    print(f"\n{DARK_RED}FALSE NEGATIVE: prompt: {prompt}")
                    print(f"{json.dumps(result, indent=4)}\n{RESET}")
                for label in labels:
                    self.label_stats[label]["FN"] += 1
        else:
            if detected:
                self.add_fp()
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
        if response.status_code != 200:
            print(f"Error fetching analyzers: {response.status_code}")
            return []
        resp_json = response.json()
        if "result" not in resp_json or "analyzers" not in resp_json["result"]:
            print("No 'result.analyzers' found in response JSON.")
            return []
        analyzers = [analyzer["name"] for analyzer in resp_json["result"]["analyzers"]]
        print(f"Fetched {len(analyzers)} analyzers: {analyzers}")
        return analyzers

    def prompt_guard_service(self, prompt, system_prompt="You're a helpful assistant."):
        """
        Insert a system prompt only if system_prompt is not None;
        otherwise skip it, exactly like the original snippet.
        """
        endpoint = "/v1beta/guard"

        # Build the messages:
        messages = [{"role": "user", "content": f"{prompt}"}]
        if system_prompt is not None:
            messages.insert(0, {"role": "system", "content": system_prompt})

        if self.analyzers_list:
            data = {"messages": [{"content": f"{prompt}", "role": "user"}], "analyzers": self.analyzers_list}
        else:
            data = {"messages": [{"content": f"{prompt}", "role": "user"}]}

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

    if args.no_system_prompt:
        system_prompt = None
    else:
        system_prompt = args.system_prompt

    @rate_limited(args.rps)
    def process_prompt(prompt, is_injection, labels, index, total_rows):
        with semaphore:
            progress = (index + 1) / total_rows * 100
            print("\r\033[2K", end="")
            print(f"{progress:.2f}%", end="\r", flush=True)
            response = pg.prompt_guard_service(prompt, system_prompt=system_prompt)
            if response.status_code != 200 and pg.verbose:
                print_response(prompt, response)
            else:
                pg.process_response(prompt, response, is_injection, labels)

    fns_out_csv = args.fns_out_csv
    fps_out_csv = args.fps_out_csv

    # Single prompt
    if args.prompt:
        response = pg.prompt_guard_service(args.prompt, system_prompt=system_prompt)
        print_response(args.prompt, response, True)
        return

    # Otherwise, read from file
    input_file = args.input_file
    file_extension = os.path.splitext(input_file)[1].lower()

    if file_extension == ".json":
        with open(input_file, "r") as file:
            data = json.load(file)
            prompts = []

            # If it's an array of items with 'text'/'label'
            if isinstance(data, list):
                for item in data:
                    text = item["text"]
                    labels = item.get("label", [])
                    inj = determine_injection(labels)
                    prompts.append((text, inj, labels))
            else:
                if not args.fp_check_only:
                    for element in data.get("tps", []):
                        prompts.append((element, True, []))
                for element in data.get("tns", []):
                    prompts.append((element, False, []))

            total_rows = len(prompts)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                for index, (prompt, inj, labels) in enumerate(prompts):
                    futures.append(executor.submit(process_prompt, prompt, inj, labels, index, total_rows))
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
                    futures.append(executor.submit(process_prompt, prompt, is_injection, [], index, total_rows))
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
    parser = argparse.ArgumentParser(
        description=(
            "Process a prompt with Prompt Guard API or read prompts from "
            "a txt (one per line), JSON (tps/tns), or CSV (SPML format)."
        )
    )
    parser.add_argument(
        "--system_prompt",
        type=str,
        help="The system prompt to use for processing the prompt (default: You're a helpful assistant.)",
        default="You're a helpful assistant.",
    )
    parser.add_argument(
        "--no_system_prompt",
        action="store_true",
        help="Do not use a system prompt for processing the prompt"
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

    args = parser.parse_args()

    # If listing analyzers, just fetch and exit
    if args.list_analyzers:
        temp_pg = PromptDetectionManager(
            rps=1.0,
            report_file_name="",
            max_poll_attempts=10,
        )
        temp_pg.prompt_guard_analyzers()
        return

    analyzers_list = args.analyzers.split(",") if args.analyzers else None

    pg = PromptDetectionManager(
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
    )

    process_all_prompts(args, pg)


if __name__ == "__main__":
    main()