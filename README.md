# CommitSV

CommitSV is a lightweight Git secret scanner for student/small-team projects.

It scans project files for possible leaked secrets such as API keys, tokens, passwords, private keys, and database URLs before they are committed to a repository.

## Features

- Recursive directory scanning
- Regex-based secret detection
- Severity labels: `HIGH`, `MEDIUM`, `LOW`
- Colored terminal output
- `--no-color` mode
- Secret masking in output
- Simple structure for adding new rules

## Requirements

- Python 3.10+

No external dependencies are required.

## Usage

Scan the current directory:

```bash
python3 commitsv.py .
```

Scan another project:

```bash
python3 commitsv.py /path/to/project
```

Disable colored output:

```bash
python3 commitsv.py . --no-color
```

Show help:

```bash
python3 commitsv.py --help
```

## Example Output

```text
[INFO] Scanning: /path/to/project

[WARNING] Found 2 potential secret(s):

[HIGH] GitHub Token
  File: /path/to/project/config.py
  Line: 3
  Match: github_token = "ghp_abc...xyz123"

[MEDIUM] Generic API Key
  File: /path/to/project/settings.py
  Line: 8
  Match: api_key = "test_api...abcdef"

[SUMMARY]
  [HIGH]   1
  [MEDIUM] 1
  [LOW]    0

[RESULT] Potential secrets found. Review before committing.
```

## What It Detects

Examples of supported detections:

- Private keys
- GitHub tokens
- AWS access keys
- Google API keys
- Telegram / Discord / Slack tokens
- Stripe and OpenAI-style keys
- JWT tokens
- Database URLs with credentials
- Generic API keys, tokens, secrets, and passwords
- Authorization headers
- `.env` and Docker Compose style secrets

## How It Works

CommitSV walks through project files, skips common generated folders and binary files, checks each text line against detection rules, and prints findings with severity levels.

Ignored examples:

```text
.git
venv
.venv
node_modules
build
dist
__pycache__
.idea
.vscode
```

## Use Cases

- Check a project before pushing to GitHub
- Scan student assignments before submission
- Review config files for hardcoded secrets
- Add later as a Git pre-commit or CI/CD check

## Disclaimer

CommitSV is an educational defensive tool. It can produce false positives and does not guarantee that a repository is completely free of secrets.
