from __future__ import annotations

from ransomware_lab.decision_tree import RuleOutcome
from ransomware_lab.i18n import Translator
from ransomware_lab.process_tree import MonitoredProcess


def percentage(share: float, decimals: int = 0) -> str:
    return f"{share * 100:.{decimals}f}%"


def process_caption(process: MonitoredProcess) -> str:
    return f"{process.image_name} ({process.pid})"


def rule_sentence(outcome: RuleOutcome, translate: Translator) -> str:
    comparison = "&le;" if outcome.satisfied else "&gt;"
    return (
        f"{translate.feature(outcome.rule.feature)} "
        f"<span>{outcome.observed:.2f} {comparison} {outcome.rule.threshold:.2f}</span>"
    )


def meter(share: float) -> str:
    width = max(0.0, min(share, 1.0)) * 100
    return f'<div class="lab-meter"><div style="width:{width:.1f}%"></div></div>'


def badge(text: str, malicious: bool) -> str:
    modifier = "malicious" if malicious else "benign"
    return f'<span class="lab-badge lab-badge--{modifier}">{text}</span>'
