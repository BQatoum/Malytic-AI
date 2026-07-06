from pathlib import Path

_SKILLS_DIR = Path(__file__).resolve().parents[3] / "skills"

_SKILL_FILES: dict[str, str] = {
    "orchestrator": "7-orchestrator-SKILL.md",
    "static_analysis": "1-static-analysis-SKILL.md",
    "dynamic_analysis": "2-dynamic-analysis-SKILL.md",
    "osint": "3-osint-research-SKILL.md",
    "attribution": "4-correlation-attribution-SKILL.md",
    "detection": "5-detection-engineering-SKILL.md",
    "report": "6-report-generation-SKILL.md",
}

_REF_FILES: dict[str, str] = {
    "static_api_categories": "ref-static-api_categories.md",
    "dynamic_reference": "ref-dynamic-reference.md",
    "mitre_reference": "ref-mitre-reference.md",
    "detection_reference": "ref-detection-reference.md",
    "orchestrator_case_file": "ref-orchestrator-case_file.md",
    "report_template": "asset-report-template.md",
}


def load_skill(phase: str) -> str:
    """Return the full text of a skill file to use as a Claude system prompt."""
    try:
        filename = _SKILL_FILES[phase]
    except KeyError:
        raise ValueError(f"Unknown phase '{phase}'. Valid phases: {list(_SKILL_FILES)}")
    return (_SKILLS_DIR / filename).read_text(encoding="utf-8")


def load_ref(name: str) -> str:
    """Return the full text of a reference file from the skills directory."""
    try:
        filename = _REF_FILES[name]
    except KeyError:
        raise ValueError(f"Unknown reference '{name}'. Valid refs: {list(_REF_FILES)}")
    return (_SKILLS_DIR / filename).read_text(encoding="utf-8")
