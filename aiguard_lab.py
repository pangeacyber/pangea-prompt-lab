#!/usr/bin/env -S poetry run python
# Copyright 2021 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from email.policy import default
from manager.aiguard_manager import AIGuardManager, AIGuardTests
from config.settings import Settings
from defaults import defaults   
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
        description="Process prompts with AI Guard API.\n\nSpecify a prompt or "
                    "input file.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    input_group = parser.add_argument_group("Input arguments")
    group = input_group.add_mutually_exclusive_group(required=True)
    group.add_argument("--prompt", type=str, help="A single prompt string to check")
    group.add_argument(
        "--input_file",
        type=str,
        help=(
            "File containing test cases to process. Supports multiple formats:\n"
            ".txt    One prompt per line.\n"
            ".jsonl  JSON Lines format, each line is test case with labels and "
            "messages array:\n"
            "        {\"label\": [\"malicious\"], \"messages\": [{\"role\": \"user\", "
            "\"content\": \"prompt\"}]}\n"
            ".json   JSON file with a tests array of test cases, each labels and a "
            "messages array:\n"
            "        {\"tests\": [{\"label\": [\"malicious\"], \"messages\": [{\"role\": "
            "\"user\", \"content\": \"prompt\"}]}]}\n"
            "        Supports optional global settings that provide defaults for all "
            "tests,\n"
            "        including a system prompt to include in any test case that "
            "doesn't have one\n"
            "        and detector configurations.\n"
            "        Each test case can specify its own settings to override global "
            "ones.\n"
            "        Each test case can specify expected_detectors in addition to or "
            "as\n"
            "        as an alternative to labels.\n"
## TODO: Document .csv format and suppot
        ),
    )

    processing_group = parser.add_argument_group("Detection and evaluation configuration")
    processing_group.add_argument(
        "--system_prompt",
        type=str,
        help="The system prompt to use for processing the prompt (default: None)",
        default=None,
    )
    processing_group.add_argument(
        "--force_system_prompt",
        action="store_true",
        help=(
            "Force a system prompt even if there is none in the test case "
            "(default: False).\n"
            "NOTE: AI Guard conformance/non-conformance checks are based on a "
            "system prompt and only happen if one is present.\n"
        )
    )
    processing_group.add_argument(
        "--detectors",
        type=str,
        default=defaults.default_detectors_str,
        help=(
            "Comma separated list of detectors to use.\n"
            + " Default:'\n"
            + defaults.default_detectors_str.replace(', ', ',\n  ') + "'\n"
            + "Use 'topic:<topic-name>' or just '<topic-name>' for topic detectors.\n"
            + "Available topic names:\n'"
            + defaults.valid_topics_str.replace(', ', ',\n  ') + "'\n"
        ),
    )
    processing_group.add_argument(
        "--topic_threshold",
        type=float,
        default=defaults.topic_threshold,
        help=(
            "Threshold for topic detection confidence. Only applies when using AI "
            f"Guard with topics. Default: {defaults.topic_threshold}."
        ),
    )    
    processing_group.add_argument(
        "--fail_fast",
        action="store_true",
        help=(
            "Enable fail-fast mode: detectors will block and exit on first "
            "detection. By default, detectors report all detections."
        ),
    )
    processing_group.add_argument(
        "--malicious_prompt_labels",
        type=str,
        default=defaults.malicious_prompt_labels_str,
        help=(
            "Comma separated list of labels indicating a malicious prompt.\n"
            + "Default:\n'" 
            + defaults.malicious_prompt_labels_str.replace(', ', ',\n  ') + "'\n"
            + "Test cases with any of these labels expect the malicious-prompt\n"
            + "detector to return a detection (FN if it does not).\n"
            + "Must not overlap with --benign_labels."
        ),
    )
    processing_group.add_argument(
        "--benign_labels",
        type=str,
        default=defaults.benign_labels_str,
        help=(
            "Comma separated list of labels indicating a benign prompt.\n"
            + "Default:\n'" 
            + defaults.benign_labels_str.replace(', ', ',\n  ') + "'\n"
            + "Test cases with any of these labels expect the malicious-prompt\n"
            + "detector NOT to return a detection (FP if it does).\n"
            + "Must not overlap with --malicious_prompt_labels."
        ),
    )
    processing_group.add_argument(
        "--recipe",
        type=str,
        help=( 
            "The recipe to use for processing the prompt.\n"
            "Useful when using --prompt for a single prompt.\n"
            "Available recipes:\n"
            "  all\n"
            + ''.join([f"  {r}\n" for r in defaults.default_recipes]) +
            f"Default: {defaults.default_recipe if defaults.default_recipe else 'None'}\n"
            "Use \"all\" to iteratively apply all recipes to the prompt (only "
            "supported for --prompt).\n\n"
            "Not appliccable when using --detectors or JSON test case objects\n"
            "that override the recipe with explicit detectors."
        ),
        default=defaults.default_recipe,
    )


    output_group = parser.add_argument_group("Output and reporting")
    output_group.add_argument(
        "--report_title",
        type=str,
        default=None,
        help="Optional title in report summary"
    )
    output_group.add_argument(
        "--summary_report_file",
        type=str,
        default=None,
        help="Optional summary report file name"
    )
    output_group.add_argument(
        "--fps_out_csv",
        type=str,
        help="Output CSV for false positives"
    )
    output_group.add_argument(
        "--fns_out_csv",
        type=str,
        help="Output CSV for false negatives"
    )
    output_group.add_argument(
        "--print_label_stats",
        action="store_true",
        help="Display per-label stats (FP/FN counts)",
    )
    output_group.add_argument(
        "--print_fps",
        action="store_true",
        help="Print false positives after summary"
    )
    output_group.add_argument(
        "--print_fns",
        action="store_true",
        help="Print false negatives after summary"
    )
    output_group.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output (FPs, FNs as they occur, full errors).",
    )
    output_group.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output (default: False)"
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
        type=int, ## TODO: Set minimum to 1 and maximum to 100?
        default=defaults.default_rps,
        help=f"Requests per second (default: {defaults.default_rps})",
    )
    performance_group.add_argument(
        "--max_poll_attempts",
        type=int,
        default=defaults.max_poll_attempts,
        help=f"Maximum poll (retry) attempts for 202 responses (default: {defaults.max_poll_attempts})",
    )
    performance_group.add_argument(
        "--fp_check_only",
        action="store_true",
        help="When passing JSON file, only check for false negatives",
        default=False,
    )

    args = parser.parse_args()

    recipe = args.recipe
    system_prompt = args.system_prompt
    if args.prompt:
        # If a single prompt, set rps to 1
        args.rps = 1

    aig = AIGuardManager(args)
    settings = Settings(system_prompt, recipe)
    aig_test = AIGuardTests(settings, aig, args)
    aig_test.process_all_prompts(args, aig)


if __name__ == "__main__":
    main()
