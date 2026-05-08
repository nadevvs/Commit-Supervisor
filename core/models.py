from dataclasses import dataclass


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    pattern: str
    description: str


@dataclass
class Finding:
    file_path: str
    line_number: int
    rule_id: str
    rule_name: str
    severity: str
    matched_text: str

