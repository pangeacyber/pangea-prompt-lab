# Copyright 2021 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

malicious_prompt_str = "malicious-prompt"
benign_str = "benign"


valid_topics = [
            "toxicity",
            "self-harm-and-violence",
            "roleplay",
            "weapons",
            "criminal-conduct",
            "sexual",
            "financial-advice",
            "legal-advice",
            "religion",
            "politics",
            "health-coverage",
            "negative-sentiment",
            "gibberish",
        ]
valid_topics_str = ", ".join(valid_topics)

# Need to be consistent with how the code handles detector names and topic names.
# Want to allow --detectors to include both detector names and topic names, and to allow
# topic names with or without the "topic:" prefix. 
# The code should allow both formats, but intenally always normalize to the "topic:<topic-name>" format.
# The valid_topics needs to be without the "topic:" prefix for use in the Overrides for the Topic detector.
valid_detectors = [
        "malicious-prompt",
        "topic",
        "code-detection",
        "competitors",
        "language-detection",
        "malicious-entity",
        "pii-entity",
        "secrets-detection",
        # TODO: NOTE: Only malicious-prompt and topic are fully supported right now.
        # NOTE: Using the overrides parameter names with undercore converted to hyphen for detector names.
        # NOTE: EXCEPT that we use "malicious-prompt" instead of "prompt-injection" for the malicious prompt detector.
        # NOTE: The AI Guard API Overrides are out of date - many were changed to topics and API is not yet updated.
        # NOTE: As the overrides parameter names change, need to update the detector names here.
        # NOTE: And the TestCase class and associated other clasees. 
        ]
# Add topic detectors prefixed with "topic:" to the valid detectors
# We also accept just the topic name without "topic:" prefix
valid_detectors.extend([f"topic:{topic}" for topic in valid_topics])

valid_detectors_str = ", ".join(valid_detectors)

default_detectors = ["malicious-prompt"]
default_detectors_str = ", ".join(default_detectors)

malicious_prompt_labels = [
    "malicious",
    "malicious_auto",
    "malicious_prompt",
    "malicious-prompt",
    "prompt-injection",
    "prompt-injection-auto",
    "adversarial_prefix",
    "adversarial_suffix",
    "direct",
    "direct_auto",
    "direct-injection",
    "indirect",
    "injection",
    "jailbreaking",
    "multi-shot",
    "not conform",
]
malicious_prompt_labels_str = ", ".join(malicious_prompt_labels)

benign_labels = [
    "benign",
    "benign_auto",
    "benign_prompt",
    "conform",
]
benign_labels_str = ", ".join(benign_labels)

topic_threshold = 1.0
topic_thresholds = {
    "toxicity": topic_threshold,
    "self-harm-and-violence": topic_threshold,
    "roleplay": topic_threshold,
    "weapons": topic_threshold,
    "criminal-conduct": topic_threshold,
    "sexual": topic_threshold,
    "financial-advice": topic_threshold,
    "legal-advice": topic_threshold,
    "religion": topic_threshold,
    "politics": topic_threshold,
    "health-coverage": topic_threshold,
    "negative-sentiment": topic_threshold,
    "gibberish": topic_threshold
}

# The built-in recipes that are available in the AI Guard service.
default_recipes = [
    "pangea_ingestion_guard",
    "pangea_prompt_guard",
    "pangea_llm_prompt_guard",
    "pangea_llm_response_guard",
    "pangea_agent_pre_plan_guard",
    "pangea_agent_pre_tool_guard",
    "pangea_agent_post_tool_guard"
]
default_recipes_str = ", ".join(default_recipes)
# Default is no recipe because you override detectors and topics
# with --detectors and/or overrides in the test case objects.
default_recipe = "pangea_prompt_guard"
default_system_prompt = (
    "You are a helpful assistant."
    "Your task is to assist the user with their queries while ensuring that the content is safe and appropriate."
)

default_rps = 15
max_rps = 100
max_poll_attempts = 12
ai_guard_token = "PANGEA_AI_GUARD_TOKEN"
pangea_domain = "PANGEA_DOMAIN"
pangea_base_url = "PANGEA_BASE_URL"
connection_timeout = 12
read_timeout = 60
ai_guard_recipe = default_recipe
ai_guard_service = "ai-guard"
ai_guard_endpoint = "v1/text/guard"
ai_guard_endpoint_url = f"{ai_guard_service}/{ai_guard_endpoint}"
ai_guard_skip_cache = False
ai_guard_system_prompt = None
ai_guard_fail_fast = False
ai_guard_detectors = default_detectors_str
ai_guard_detectors_list = ai_guard_detectors.split(",")
ai_guard_malicious_prompt_labels = malicious_prompt_labels
ai_guard_benign_labels = benign_labels
ai_guard_malicious_prompt_labels_str = ",".join(ai_guard_malicious_prompt_labels)
ai_guard_benign_labels_str = ",".join(ai_guard_benign_labels)
ai_guard_topic_threshold = topic_threshold
