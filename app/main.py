"""HTTP API for password analysis, generation, and TOTP operations."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import string
from typing import Annotated

import pyotp
import requests
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from zxcvbn import zxcvbn


_HIBP_RANGE_URL = os.getenv(
    "HIBP_RANGE_URL", "https://api.pwnedpasswords.com/range"
).rstrip("/")
_HIBP_TIMEOUT_SECONDS = float(os.getenv("HIBP_TIMEOUT_SECONDS", "5"))
_PASSWORD_ALPHABET = string.ascii_lowercase
_SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{};:,.?/|~"
_PASSPHRASE_HARDENING_CHARACTERS = string.digits + "!@#$%^&*"


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PasswordRequest(APIModel):
    password: SecretStr = Field(min_length=1, max_length=256)


class CustomPassphraseRequest(APIModel):
    description: str = Field(min_length=1, max_length=300)
    length: int = Field(default=8, ge=6, le=16)
    separator: str = Field(default="-", min_length=1, max_length=8)


class PasswordFeedback(APIModel):
    warning: str
    suggestions: list[str]


class PasswordStrengthResponse(APIModel):
    score: int = Field(ge=0, le=4)
    feedback: PasswordFeedback
    estimated_crack_time: dict[str, str]


class TwoFactorGenerateRequest(APIModel):
    account_name: str = Field(min_length=1, max_length=200)
    issuer: str = Field(default="Password Security", min_length=1, max_length=64)


class TwoFactorGenerateResponse(APIModel):
    secret: str
    provisioning_uri: str


class TwoFactorVerifyRequest(APIModel):
    secret: SecretStr = Field(min_length=16, max_length=128)
    token: str = Field(pattern=r"^\d{6}$")

    @field_validator("secret")
    @classmethod
    def validate_secret(cls, secret: SecretStr) -> SecretStr:
        if re.fullmatch(r"[A-Z2-7]{16,128}", secret.get_secret_value()) is None:
            raise ValueError("Secret must be a Base32 string.")
        return secret


class TwoFactorVerifyResponse(APIModel):
    valid: bool


class BreachCheckResponse(APIModel):
    compromised: bool
    breach_count: int = Field(ge=0)


app = FastAPI(
    title="Password Security API",
    description="Password strength, secure generation, TOTP, and breach analysis.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.post(
    "/api/v1/password/strength",
    response_model=PasswordStrengthResponse,
    summary="Evaluate password strength",
)
def password_strength(request: PasswordRequest) -> PasswordStrengthResponse:
    """Evaluate the supplied password without returning or logging it."""
    result = zxcvbn(request.password.get_secret_value())
    return PasswordStrengthResponse(
        score=result["score"],
        feedback=PasswordFeedback(
            warning=result["feedback"]["warning"] or "",
            suggestions=result["feedback"]["suggestions"],
        ),
        estimated_crack_time=result["crack_times_display"],
    )


@app.get(
    "/api/v1/password/generate",
    summary="Generate a cryptographically secure password",
)
def generate_password(
    length: Annotated[int, Query(ge=8, le=128)] = 20,
    digits: bool = True,
    uppercase: bool = True,
    special: bool = True,
) -> dict[str, str]:
    """Generate a password containing each enabled character category."""
    alphabet = _PASSWORD_ALPHABET
    required_characters = []
    if digits:
        alphabet += string.digits
        required_characters.append(secrets.choice(string.digits))
    if uppercase:
        alphabet += string.ascii_uppercase
        required_characters.append(secrets.choice(string.ascii_uppercase))
    if special:
        alphabet += _SPECIAL_CHARACTERS
        required_characters.append(secrets.choice(_SPECIAL_CHARACTERS))

    password_characters = required_characters + [
        secrets.choice(alphabet) for _ in range(length - len(required_characters))
    ]
    for index in range(len(password_characters) - 1, 0, -1):
        swap_index = secrets.randbelow(index + 1)
        password_characters[index], password_characters[swap_index] = (
            password_characters[swap_index],
            password_characters[index],
        )
    return {"password": "".join(password_characters)}


def _harden_passphrase_part(token: str, *, force_decoration: bool = False) -> str:
    characters = [
        secrets.choice((character.lower(), character.upper()))
        if character in string.ascii_letters
        else character
        for character in token
    ]
    if force_decoration or secrets.randbelow(4) == 0:
        characters[secrets.randbelow(len(characters))] = secrets.choice(
            _PASSPHRASE_HARDENING_CHARACTERS
        )

    letter_positions = [
        index
        for index, character in enumerate(characters)
        if character in string.ascii_letters
    ]
    if len(letter_positions) >= 2:
        has_lowercase = any(
            characters[index] in string.ascii_lowercase for index in letter_positions
        )
        has_uppercase = any(
            characters[index] in string.ascii_uppercase for index in letter_positions
        )
        if not has_lowercase:
            lower_index = secrets.choice(letter_positions)
            characters[lower_index] = characters[lower_index].lower()
            upper_candidates = [
                index for index in letter_positions if index != lower_index
            ]
            upper_index = secrets.choice(upper_candidates)
            characters[upper_index] = characters[upper_index].upper()
        elif not has_uppercase:
            upper_index = secrets.choice(letter_positions)
            characters[upper_index] = characters[upper_index].upper()

    return "".join(characters)


@app.post(
    "/api/v1/passphrase/generate-from-description",
    summary="Text-based Passphrase Generation",
)
def generate_text_based_passphrase(
    request: CustomPassphraseRequest,
) -> dict[str, str | int]:
    """Build a passphrase from unique tokens in a user-provided description."""
    tokens = list(
        dict.fromkeys(
            token
            for token in re.findall(r"[^\W_]+", request.description.lower())
            if len(token) >= 2
        )
    )
    if not tokens:
        raise HTTPException(
            status_code=400,
            detail="Description must contain at least one alphanumeric token with two or more characters.",
        )

    passphrase_parts: list[str] = []
    unique_parts: set[str] = set()
    for index, token in enumerate(tokens[: request.length]):
        while True:
            part = _harden_passphrase_part(token, force_decoration=index == 0)
            if part not in unique_parts:
                passphrase_parts.append(part)
                unique_parts.add(part)
                break

    while len(passphrase_parts) < request.length:
        base_token = secrets.choice(tokens)
        variant = _harden_passphrase_part(base_token, force_decoration=True)
        if variant not in unique_parts:
            passphrase_parts.append(variant)
            unique_parts.add(variant)

    return {
        "passphrase": request.separator.join(passphrase_parts),
        "word_count": len(passphrase_parts),
    }


@app.post(
    "/api/v1/2fa/generate",
    response_model=TwoFactorGenerateResponse,
    summary="Create a TOTP secret and provisioning URI",
)
def generate_two_factor(
    request: TwoFactorGenerateRequest,
) -> TwoFactorGenerateResponse:
    """Generate a new Base32 secret and an authenticator-compatible URI."""
    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=request.account_name,
        issuer_name=request.issuer,
    )
    return TwoFactorGenerateResponse(secret=secret, provisioning_uri=uri)


@app.post(
    "/api/v1/2fa/verify",
    response_model=TwoFactorVerifyResponse,
    summary="Verify a six-digit TOTP token",
)
def verify_two_factor(request: TwoFactorVerifyRequest) -> TwoFactorVerifyResponse:
    """Verify the token for the current 30-second TOTP interval."""
    valid = pyotp.TOTP(request.secret.get_secret_value()).verify(
        request.token, valid_window=0
    )
    return TwoFactorVerifyResponse(valid=valid)


@app.post(
    "/api/v1/password/breach-check",
    response_model=BreachCheckResponse,
    summary="Check a password against HIBP using k-anonymity",
)
def check_password_breach(request: PasswordRequest) -> BreachCheckResponse:
    """Send only the first five SHA-1 hex characters to the HIBP range API."""
    password_hash = hashlib.sha1(
        request.password.get_secret_value().encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest().upper()
    prefix, suffix = password_hash[:5], password_hash[5:]

    try:
        response = requests.get(
            f"{_HIBP_RANGE_URL}/{prefix}",
            headers={
                "Add-Padding": "true",
                "User-Agent": "PasswordSecurityAPI/1.0",
            },
            timeout=_HIBP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502, detail="The breach-check provider is unavailable."
        ) from exc

    breach_count = 0
    for line in response.text.splitlines():
        if not line:
            continue
        parts = line.split(":")
        if (
            len(parts) != 2
            or len(parts[0]) != 35
            or any(character not in string.hexdigits for character in parts[0])
        ):
            raise HTTPException(
                status_code=502, detail="The breach-check provider returned invalid data."
            )
        try:
            count = int(parts[1])
        except ValueError as exc:
            raise HTTPException(
                status_code=502, detail="The breach-check provider returned invalid data."
            ) from exc
        if count < 0:
            raise HTTPException(
                status_code=502, detail="The breach-check provider returned invalid data."
            )
        if hmac.compare_digest(parts[0].upper(), suffix):
            breach_count = count
    return BreachCheckResponse(
        compromised=breach_count > 0,
        breach_count=breach_count,
    )
