#!/usr/bin/env -S poetry run python
# Copyright 2021 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from manager.aiguard_manager import AIGuardManager, AIGuardTests
from config.settings import Settings
import argparse


def determine_injection(labels):
    """Heuristic to decide if this is injection or not based on labels."""
    benign_labels = {"benign_auto", "benign"}
    if any(label in benign_labels for label in labels):
        return False
    else:
        return True  # Assume injection if not labeled as benign


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Process prompts with AI Guard API.  "
            "Specify a prompt or input file."
        )
    )

    input_group = parser.add_argument_group("Input arguments")
    group = input_group.add_mutually_exclusive_group(required=True)
    group.add_argument("--prompt", type=str, help="A single prompt string to check")
    group.add_argument(
        "--input_file",
        type=str,
        help=(
            'File containing prompts: .txt - one per line, .json - File with optional global "settings" '
            'object and "tests" list of test cases (each can have own "settings" object to override) of messages array'
        ),
    )

    processing_group = parser.add_argument_group("Detection and evaluation configuration")
    processing_group.add_argument(
        "--detectors",
        type=str,
        default="malicious-prompt",
        help=(
            "Comma separated list of detectors to use (default: 'malicious-prompt'). "
            "Use 'topic:<topic-name>' or just '<topic-name>' for topic detectors. "
            "Available topic names: toxicity, self-harm-and-violence, roleplay, weapons, criminal-conduct, "
            "sexual, financial-advice, legal-advice, religion, politics, health-coverage, "
            "negative-sentiment, gibberish. "
        ),
    )
    processing_group.add_argument(
        "--topic_threshold",
        type=float,
        default=1.0,
        help=(
            "Threshold for topic detection confidence. "
            "Only applies when using AI Guard with topics. Default: 1.0"
        ),
    )    
    processing_group.add_argument(
        "--fail_fast",
        action="store_true",
        help=(
            "Enable fail-fast mode: detectors will block on first detection. "
            "By default, detectors report all detections."
        ),
    )
    processing_group.add_argument(
        "--malicious_prompt_labels",
        type=str,
        default="malicious-prompt,injection",
        help=(
            "Comma separated list of labels indicating malicious prompt injections (default: 'malicious-prompt,injection'). "
            "These labels are used to identify expected malicious prompts in the input dataset."
        ),
    )
    processing_group.add_argument(
        "--benign_labels",
        type=str,
        default="benign,conforming",
        help=(
            "Comma separated list of labels indicating benign prompts (default: 'benign,conforming'). "
            "These label values are used to identify expected benign prompts in the input dataset.  "
            "A dataset element with a benign-label can have no other labels."
        ),
    )
    processing_group.add_argument(
        "--system_prompt",
        type=str,
        help="The system prompt to use for processing the prompt (default: None)",
        default=None,
    )
    processing_group.add_argument(
        "--recipe",
        type=str,
        help="""The recipe to use for processing the prompt:

        (pangea_ingestion_guard | pangea_prompt_guard | pangea_llm_prompt_guard | pangea_llm_response_guard |
        pangea_agent_pre_plan_guard | pangea_agent_pre_tool_guard | pangea_agent_post_tool_guard)

        Default: "pangea_prompt_guard"

        Use "all" to apply all recipes (only supported for single prompt)""",
        default=None,
    )


    output_group = parser.add_argument_group("Output and reporting")
    output_group.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output (FPs, FNs as they occur, full errors).",
    )
    output_group.add_argument("--debug", action="store_true", help="Enable debug output (default: False)")
    output_group.add_argument("--report_title", type=str, default=None, help="Optional title in report summary")
    output_group.add_argument("--summary_report_file", type=str, default=None, help="Optional summary report file name")
    output_group.add_argument("--print_fps", action="store_true", help="Print false positives at the end")
    output_group.add_argument("--print_fns", action="store_true", help="Print false negatives at the end")
    output_group.add_argument("--fps_out_csv", type=str, help="Output CSV for false positives")
    output_group.add_argument("--fns_out_csv", type=str, help="Output CSV for false negatives")
    output_group.add_argument(
        "--print_label_stats",
        action="store_true",
        help="Display per-label stats (FP/FN counts)",
    )    

    assumption_group = parser.add_argument_group("Assumptions for plain text prompts")
    group_tp_tn = assumption_group.add_mutually_exclusive_group(required=False)
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

    performance_group = parser.add_argument_group("Performance")
    performance_group.add_argument(
        "--rps",
        type=int,
        default=1,
        help="Requests per second (default: 1)",
    )
    performance_group.add_argument(
        "--max_poll_attempts",
        type=int,
        default=12,
        help="Maximum poll attempts for 202 responses (default: 12)",
    )
    performance_group.add_argument(
        "--fp_check_only",
        action="store_true",
        help="When passing JSON file, only check for false negatives",
        default=False,
    )

    args = parser.parse_args()

    prompt = args.prompt
    recipe = args.recipe
    system_prompt = args.system_prompt

    aig = AIGuardManager(args)
    settings = Settings(system_prompt, recipe or "pangea_prompt_guard")
    aig_test = AIGuardTests(settings, args)
    aig_test.process_all_prompts(args, aig)


if __name__ == "__main__":
    main()
