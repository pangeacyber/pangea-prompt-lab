# Copyright 2021 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from dataclasses import dataclass
from typing import Optional


@dataclass
class CodeDetection:
    disabled: Optional[bool] = None
    action: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "CodeDetection":
        if not data:
            return cls()
        return cls(
            disabled=data.get("disabled"),
            action=data.get("action"),
        )


@dataclass
class Competitors:
    disabled: Optional[bool] = None
    action: Optional[str] = None
    competitors: Optional[list[str]] = None

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "Competitors":
        if not data:
            return cls()
        return cls(**data)


@dataclass
class LanguageDetection:
    disabled: Optional[bool] = None
    action: Optional[str] = None
    languages: Optional[list[str]] = None

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "LanguageDetection":
        if not data:
            return cls()
        return cls(**data)


@dataclass
class MaliciousEntity:
    disabled: Optional[bool] = None
    url: Optional[str] = None
    ip_address: Optional[str] = None
    domain: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "MaliciousEntity":
        if not data:
            return cls()
        return cls(**data)


@dataclass
class PIIEntity:
    disabled: Optional[bool] = None
    email_address: Optional[str] = None
    nrp: Optional[str] = None
    location: Optional[str] = None
    person: Optional[str] = None
    phone_number: Optional[str] = None
    date_time: Optional[str] = None
    ip_address: Optional[str] = None
    url: Optional[str] = None
    money: Optional[str] = None
    credit_card: Optional[str] = None
    crypto: Optional[str] = None
    iban_code: Optional[str] = None
    us_bank_number: Optional[str] = None
    nif: Optional[str] = None
    fin_nric: Optional[str] = None
    au_abn: Optional[str] = None
    au_acn: Optional[str] = None
    au_tfn: Optional[str] = None
    medical_license: Optional[str] = None
    uk_nhs: Optional[str] = None
    au_medicare: Optional[str] = None
    us_drivers_license: Optional[str] = None
    us_itin: Optional[str] = None
    us_passport: Optional[str] = None
    us_ssn: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "PIIEntity":
        if not data:
            return cls()
        return cls(**data)


@dataclass
class PromptInjection:
    disabled: Optional[bool] = None
    action: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "PromptInjection":
        if not data:
            return cls()
        return cls(**data)


@dataclass
class SecretsDetection:
    disabled: Optional[bool] = None
    slack_token: Optional[str] = None
    ssh_dsa_private_key: Optional[str] = None
    ssh_ec_private_key: Optional[str] = None
    pgp_private_key_block: Optional[str] = None
    amazon_aws_access_key_id: Optional[str] = None
    amazon_aws_secret_access_key: Optional[str] = None
    amazon_mws_auth_token: Optional[str] = None
    facebook_access_token: Optional[str] = None
    github_access_token: Optional[str] = None
    jwt_token: Optional[str] = None
    google_api_key: Optional[str] = None
    google_cloud_platform_api_key: Optional[str] = None
    google_drive_api_key: Optional[str] = None
    google_cloud_platform_service_account: Optional[str] = None
    google_gmail_api_key: Optional[str] = None
    youtube_api_key: Optional[str] = None
    mailchimp_api_key: Optional[str] = None
    mailgun_api_key: Optional[str] = None
    basic_auth: Optional[str] = None
    picatic_api_key: Optional[str] = None
    slack_webhook: Optional[str] = None
    stripe_api_key: Optional[str] = None
    stripe_restricted_api_key: Optional[str] = None
    square_access_token: Optional[str] = None
    square_oauth_secret: Optional[str] = None
    twilio_api_key: Optional[str] = None
    pangea_token: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "SecretsDetection":
        if not data:
            return cls()
        return cls(**data)


@dataclass
class Topic:
    disabled: Optional[bool] = None
    action: Optional[str] = None
    threshold: Optional[float] = None
    topics: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "Topic":
        if not data:
            return cls()
        return cls(**data)
