from core.models import Rule


SECRET_RULES = [
    Rule(
        id="private-key",
        name="Private Key",
        severity="HIGH",
        pattern=r"-----BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE) PRIVATE KEY-----",
        description="Private key material was found."
    ),
    Rule(
        id="generic-api-key",
        name="Generic API Key",
        severity="MEDIUM",
        pattern=r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?",
        description="Possible API key assignment was found."
    ),
    Rule(
        id="generic-secret",
        name="Generic Secret",
        severity="MEDIUM",
        pattern=r"(?i)(secret|client_secret|app_secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}['\"]?",
        description="Possible secret value was found."
    ),
    Rule(
        id="password-assignment",
        name="Password Assignment",
        severity="MEDIUM",
        pattern=r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{6,}['\"]?",
        description="Possible hardcoded password was found."
    ),
    Rule(
        id="jwt-token",
        name="JWT Token",
        severity="HIGH",
        pattern=r"eyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+",
        description="Possible JWT token was found."
    ),
    Rule(
        id="aws-access-key",
        name="AWS Access Key ID",
        severity="HIGH",
        pattern=r"AKIA[0-9A-Z]{16}",
        description="Possible AWS access key ID was found."
    ),
    Rule(
        id="github-token",
        name="GitHub Token",
        severity="HIGH",
        pattern=r"gh[pousr]_[A-Za-z0-9_]{30,}",
        description="Possible GitHub token was found."
    ),
    Rule(
        id="database-url",
        name="Database URL",
        severity="HIGH",
        pattern=r"(?i)(postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^ \n]+",
        description="Possible database connection string with credentials was found."
    ),
    Rule(
        id="env-secret-style",
        name=".env Secret Style",
        severity="MEDIUM",
        pattern=r"(?i)^[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*=.*",
        description="Possible secret in .env-style format was found."
    )
]
