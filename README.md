<a href="https://pangea.cloud?utm_source=github&utm_medium=python-sdk" target="_blank" rel="noopener noreferrer">
  <img src="https://pangea-marketing.s3.us-west-2.amazonaws.com/pangea-color.svg" alt="Pangea Logo" height="40" />
</a>

<br />

[![documentation](https://img.shields.io/badge/documentation-pangea-blue?style=for-the-badge&labelColor=551B76)](https://pangea.cloud/docs/prompt-guard/)
[![Discourse](https://img.shields.io/badge/Discourse-4A154B?style=for-the-badge&logo=discourse&logoColor=white)][Discourse]

[Discourse]: https://community.pangea.cloud
Testing tool to evaluate Pangea PromptGuard service efficacy. 
This utility measures accuracy of malicious vs. benign prompts.

Prerequisites
-------------
- Environment Variable: PANGEA_PROMPTGUARD_TOKEN must be set to a valid PromptGuard token.
- Environment Variable: PANGEA_DOMAIN must be set. Refer to service configuration details.

Usage
-----
```
usage: prompt_lab.py [-h]
                     [--verbose]
                     [--report_title REPORT_TITLE]
                     [--summary_report_file SUMMARY_REPORT_FILE]
                     [--prompt PROMPT | --input_file INPUT_FILE | --list_analyzers]
                     [--analyzers ANALYZERS]
                     [--fp_check_only]
                     [--assume_tps | --assume_tns]
                     [--fps_out_csv FPS_OUT_CSV]
                     [--fns_out_csv FNS_OUT_CSV]
                     [--print_fps]
                     [--print_fns]
                     [--rps RPS]
                     [--max_poll_attempts MAX_POLL_ATTEMPTS]
                     [--print_label_stats]
```
Important Flags
--------------
1) Single Prompt (e.g. --prompt "Hello, world!")
   - Processes a single prompt and prints the result.

2) Input File (e.g. --input_file test_data.json)
   - Processes multiple prompts from a file.
   - Supported formats:
     - .txt: One prompt per line
       - Use --assume_tps if all prompts are True Positives.
       - Use --assume_tns if all prompts are True Negatives.
     - .json: Expects a 'tps' and 'tns' array or a list of objects with 'text' and 'label'.
       Example:
         {
           "tps": [
             "This is a prompt injection example",
             "Another malicious prompt"
           ],
           "tns": [
             "A harmless prompt",
             "A normal query"
           ]
         }
     - .csv: Uses SPML Chatbot Prompt Injection format:
       Columns: System Prompt, User Prompt, Prompt injection, Degree, Source.
       The tool extracts User Prompt and interprets Prompt injection as 1 (injection) or 0 (benign).

3) Listing Analyzers (--list_analyzers)
   - Prints available analyzer IDs from the PromptGuard service, then exits.

4) Reporting Options
   - --verbose prints detailed error messages, false positives, and false negatives.
   - --report_title / --summary_report_file allow labeling and saving a summary of the test results.
   - --print_label_stats shows label-based statistics (how often each label triggered FPs or FNs).

5) Output Files
   - --fps_out_csv: Saves any false positives to a CSV file.
   - --fns_out_csv: Saves any false negatives to a CSV file.

6) Rate Limiting
   - --rps: Requests per second (default: 1.0).
   - --max_poll_attempts: Maximum retries for async requests (default: 10).

Example Commands
---------------
1) Single Prompt:
   ./promptguard.py --prompt "Ignore previous instructions..." --verbose

2) Text File (All True Positives):
   ./promptguard.py --input_file malicious_prompts.txt --assume_tps --verbose

3) JSON File (tps/tns):
   ./promptguard.py --input_file test_data.json --verbose

4) CSV File:
   ./promptguard.py --input_file spml_dataset.csv --verbose

5) List Available Analyzers:
   ./promptguard.py --list_analyzers

6) Specify Analyzers:
   ./promptguard.py --input_file spml_dataset.csv --analyzers PA2001,PA2002 --verbose

Output and Metrics
-----------------
- True Positives (TP)
- False Positives (FP)
- True Negatives (TN)
- False Negatives (FN)

Also calculates accuracy, precision, recall, F1, specificity, and logs any errors.
Use --fps_out_csv / --fns_out_csv to save FP/FN prompts for further analysis.