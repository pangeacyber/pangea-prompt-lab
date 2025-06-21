# Copyright 2021 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import os
import time
import json
import requests
from requests.models import Response
from urllib.parse import urljoin
from utils.colors import DARK_RED, DARK_YELLOW, DARK_BLUE, DARK_GREEN, RED, RESET
from defaults import defaults


ai_guard_token = os.getenv(defaults.ai_guard_token)
assert ai_guard_token, f"{defaults.ai_guard_token} environment variable not set"
# domain = os.getenv(defaults.pangea_domain)
# assert domain, f"{defaults.pangea_domain} environment variable not set"
base_url = os.getenv(defaults.pangea_base_url)
assert base_url, f"{defaults.pangea_base_url} environment variable not set"



connection_timeout = defaults.connection_timeout
# Default is 12 seconds, but can be overridden by the user
read_timeout = defaults.read_timeout


def create_error_response(status_code, message):
    """Create a mock error response."""
    # Create a new Response object
    response = Response()

    # Set the status code to simulate the error
    response.status_code = status_code

    # Set the response content as JSON, with a 'status' field
    error_content = {"status": status_code, "message": message}

    # Convert the dictionary to JSON and encode it as bytes for _content
    response._content = json.dumps(error_content).encode("utf-8")
    return response


def pangea_post_api(service, endpoint, data, skip_cache=False, token=ai_guard_token, base_url=base_url):
    try:
        url = urljoin(base_url, endpoint) # TODO: fix this to use service, endpoint, domain or base_url
        # print(f"POST {url} with data: {data}")
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        if skip_cache:
            headers["x-pangea-skipcache"] = "true"  # avoid caching
        # print(f"POST {url}, headers: {headers}, data: {data}")
        response = requests.post(url, headers=headers, json=data, timeout=(connection_timeout, read_timeout))
        if response is None:
            # Simulate an error response if the actual response is None or status code isn't 200
            return create_error_response(500, "Internal server error: failed to fetch data")
        return response
    except requests.exceptions.Timeout:
        return create_error_response(408, "Request Timeout")
    except requests.exceptions.RequestException as e:
        return create_error_response(400, f"Bad Request: {e}")


def pangea_get_api(endpoint, token=ai_guard_token, base_url=base_url):
    try:
        url = urljoin(base_url, endpoint) # TODO: fix this to use service, endpoint, domain or base_url
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        response = requests.get(url, headers=headers, timeout=(connection_timeout, read_timeout))
        return response
    except requests.exceptions.Timeout:
        return create_error_response(408, "Request Timeout")
    except requests.exceptions.RequestException as e:
        return create_error_response(400, f"Bad Request: {e}")


def pangea_request(request_id, token=ai_guard_token, base_url=base_url):
    # service = "ai-guard"
    endpoint = f"/request/{request_id}"
    return pangea_get_api(endpoint, token=token, base_url=base_url)


def poll_request(request_id, max_attempts=12, verbose=False, token=ai_guard_token, base_url=base_url):
    """
    Poll status until 'Success' or non-202 result, or max attempts reached.
    """
    status_code = "Accepted"
    response = None
    counter = 1
    if verbose:
        print(f"\nPolling for response using URL: {base_url}/request/{request_id}")
    while status_code == "Accepted":
        response = pangea_request(request_id, token=token, base_url=base_url)
        if response is None:
            if verbose:
                print(f"\n{DARK_YELLOW}poll_request failed with no response." f"{RESET}")
            break
        # print(
        #     f"\nRaw response: {response} "
        #     f"response.json: {response.json()}\n"
        # )
        status_code = response.json()["status"]
        if verbose:
            print(f" {DARK_BLUE}{counter}{RESET} : " f"Polling status code is {status_code} ...", end="\r")
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
                print(f"\n{RED}Max attempts reached. " f"Exiting polling loop.{RESET}")
            break
        time.sleep(5)
        counter += 1
    return status_code, response
