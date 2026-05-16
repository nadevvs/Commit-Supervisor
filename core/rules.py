from core.models import Rule


SECRET_RULES = [
    Rule(
        id="private-key",
        name="Private Key",
        severity="HIGH",
        pattern=r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        description="Private key material was found."
    ),
    Rule(
        id="google-service-account-key",
        name="Google Service Account Key",
        severity="HIGH",
        pattern=r'"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----',
        description="Possible Google service account private key was found."
    ),
    Rule(
        id="github-token",
        name="GitHub Token",
        severity="HIGH",
        pattern=r"gh[pousr]_[A-Za-z0-9_]{30,}",
        description="Possible GitHub token was found."
    ),
    Rule(
        id="aws-access-key",
        name="AWS Access Key ID",
        severity="HIGH",
        pattern=r"AKIA[0-9A-Z]{16}",
        description="Possible AWS access key ID was found."
    ),
    Rule(
        id="google-api-key",
        name="Google API Key",
        severity="HIGH",
        pattern=r"AIza[A-Za-z0-9_-]{35}",
        description="Possible Google API key was found."
    ),
    Rule(
        id="telegram-bot-token",
        name="Telegram Bot Token",
        severity="HIGH",
        pattern=r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b",
        description="Possible Telegram bot token was found."
    ),
    Rule(
        id="discord-bot-token",
        name="Discord Bot Token",
        severity="HIGH",
        pattern=r"\b[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b",
        description="Possible Discord bot token was found."
    ),
    Rule(
        id="slack-token",
        name="Slack Token",
        severity="HIGH",
        pattern=r"xox[baprs]-[A-Za-z0-9-]{10,}",
        description="Possible Slack token was found."
    ),
    Rule(
        id="stripe-secret-key",
        name="Stripe Secret Key",
        severity="HIGH",
        pattern=r"sk_(live|test)_[A-Za-z0-9]{24,}",
        description="Possible Stripe secret key was found."
    ),
    Rule(
        id="openai-api-key",
        name="OpenAI API Key",
        severity="HIGH",
        pattern=r"sk-[A-Za-z0-9]{32,}",
        description="Possible OpenAI API key was found."
    ),
    Rule(
        id="jwt-token",
        name="JWT Token",
        severity="HIGH",
        pattern=r"eyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+",
        description="Possible JWT token was found."
    ),
    Rule(
        id="database-url",
        name="Database URL",
        severity="HIGH",
        pattern=r"(?i)(postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^ \n]+",
        description="Possible database connection string with credentials was found."
    ),
    Rule(
        id="basic-auth-url",
        name="URL With Embedded Credentials",
        severity="HIGH",
        pattern=r"https?:\/\/[^:\s\/]+:[^@\s\/]+@[^ \n]+",
        description="Possible URL with embedded username and password was found."
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
        id="generic-token",
        name="Generic Token",
        severity="MEDIUM",
        pattern=r"(?i)(token|access_token|auth_token|refresh_token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}['\"]?",
        description="Possible generic token assignment was found."
    ),
    Rule(
        id="password-assignment",
        name="Password Assignment",
        severity="MEDIUM",
        pattern=r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{6,}['\"]?",
        description="Possible hardcoded password was found."
    ),
    Rule(
        id="config-password",
        name="Config Password",
        severity="MEDIUM",
        pattern=r"(?i)['\"]?(password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{6,}['\"]",
        description="Possible password in config file was found."
    ),
    Rule(
        id="authorization-header",
        name="Hardcoded Authorization Header",
        severity="MEDIUM",
        pattern=r"(?i)authorization\s*[:=]\s*['\"]?(Bearer|Basic)\s+[A-Za-z0-9_\-.:+/=]{10,}",
        description="Possible hardcoded Authorization header was found."
    ),
    Rule(
        id="env-secret-style",
        name=".env Secret Style",
        severity="MEDIUM",
        pattern=r"(?i)^[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*=.*",
        description="Possible secret in .env-style format was found."
    ),
    Rule(
        id="docker-env-secret",
        name="Docker Environment Secret",
        severity="MEDIUM",
        pattern=r"(?i)-\s*[A-Z0-9_]*(PASSWORD|TOKEN|SECRET|KEY)[A-Z0-9_]*=.+",
        description="Possible secret in Docker Compose environment variable was found."
    ),
]