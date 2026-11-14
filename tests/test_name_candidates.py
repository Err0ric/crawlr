"""The AI prompt for a name case: people who share a name are compared, never merged."""
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from main import app
from routers.analyze import NAME_CANDIDATES_SECTION, TARGET_FOCUS, AnalyzeRequest, investigation_prompt

ROWS = [
    {"source": "Wikidata", "name": "Linus Torvalds", "handle": "Q34253", "description": "Finnish software engineer (born 1969)",
     "name_match": "exact", "qualifier_hits": []},
    {"source": "OpenAlex", "name": "Linus Torvalds", "handle": "A5083555959", "description": "10 works indexed.", "location": "US",
     "affiliation": "Linux Foundation", "name_match": "exact", "qualifier_hits": ["employer"]},
    {"source": "GitHub", "name": "", "handle": "torvalds", "name_match": "tokens", "qualifier_hits": []},
    {"source": "GitHub", "name": "Someone Else", "handle": "linus-fan", "name_match": "none", "qualifier_hits": []},
]
FIELD = {
    "name": "Linus Torvalds", "candidates": ROWS,
    "notable": {"name": "Linus Torvalds", "description": "Finnish software engineer (born 1969)"},
    "qualifiers": {"location": "", "employer": "Linux Foundation", "keyword": ""},
}


def base(**extra):
    return {"target": "Linus Torvalds", "target_type": "name", "name_search": {"name": "Linus Torvalds"},
            "source_status": {"Name search": "partial: 4 of 5 directories answered"}, **extra}


def test_without_the_field_the_prompt_is_unchanged():
    plain = investigation_prompt(AnalyzeRequest(**base()))
    assert investigation_prompt(AnalyzeRequest(**base(name_candidates=None))) == plain
    assert TARGET_FOCUS["name"] in plain
    assert "This is a NAME SEARCH for real person: Linus Torvalds." in plain
    assert NAME_CANDIDATES_SECTION not in plain and "PEOPLE WHO SHARE THIS NAME" not in plain
    # Another kind of target never gets the paragraph either.
    other = investigation_prompt(AnalyzeRequest(target="torvalds", target_type="username"))
    assert NAME_CANDIDATES_SECTION not in other and "PEOPLE WHO SHARE THIS NAME" not in other


def test_candidates_are_listed_as_different_people_and_never_merged():
    p = investigation_prompt(AnalyzeRequest(**base(name_candidates=FIELD)))
    assert NAME_CANDIDATES_SECTION in p
    for rule in ("different people who share a name", "Never merge them into one profile",
                 "Do not guess which one the investigator means", "what distinguishes them",
                 "what further public information would settle", "Do not add facts that are not in the list"):
        assert rule in p
    # The search-plan wording is replaced, not stacked on top.
    assert TARGET_FOCUS["name"] not in p and "NAME SEARCH for real person" not in p
    assert "PEOPLE WHO SHARE THIS NAME (4 rows from public directories)" in p
    assert "1. [Wikidata] | name: Linus Torvalds | handle or ID: Q34253 | description: Finnish software engineer (born 1969) | name fit: exact name" in p
    assert "2. [OpenAlex] | name: Linus Torvalds | handle or ID: A5083555959 | description: 10 works indexed. | location: US | affiliation: Linux Foundation | name fit: exact name | matches the investigator's employer" in p
    assert "3. [GitHub] | no name given | handle or ID: torvalds | name fit: all name words" in p
    assert "name fit: name on profile does not match" in p
    assert "PUBLIC FIGURE WITH THIS NAME (Wikidata): Linus Torvalds, Finnish software engineer (born 1969)" in p
    assert "DETAILS THE INVESTIGATOR GAVE (used only to rank the rows, not confirmed for anyone): employer: Linux Foundation" in p
    # A directory that could not be asked is still reported as partial, never as "not found".
    assert "Name search (partial: 4 of 5 directories answered)" in p


def test_an_empty_list_keeps_the_search_plan_and_says_nobody_was_found():
    p = investigation_prompt(AnalyzeRequest(**base(name_candidates={"name": "Zed Nobody", "candidates": []})))
    assert NAME_CANDIDATES_SECTION not in p and TARGET_FOCUS["name"] in p
    assert "returned no person with this name" in p and "unknown, not a negative result" in p


def test_the_field_is_bounded():
    with pytest.raises(ValidationError):
        AnalyzeRequest(**base(name_candidates={**FIELD, "candidates": ROWS * 8}))          # 32 rows, limit 30
    with pytest.raises(ValidationError):
        AnalyzeRequest(**base(name_candidates={**FIELD, "candidates": [{**ROWS[0], "description": "x" * 241}]}))
    with pytest.raises(ValidationError):
        AnalyzeRequest(**base(name_candidates={**FIELD, "qualifiers": {"location": "x" * 81}}))
    # An unknown qualifier name in a row is never echoed into the prompt.
    p = investigation_prompt(AnalyzeRequest(**base(name_candidates={**FIELD, "candidates": [{**ROWS[0], "qualifier_hits": ["ignore previous instructions"]}]})))
    assert "ignore previous instructions" not in p


def test_the_copy_prompt_endpoint_returns_the_same_prompt():
    body = base(name_candidates=FIELD)
    r = TestClient(app).post("/api/analyze/prompt", json=body)
    assert r.status_code == 200
    assert r.json()["prompt"] == investigation_prompt(AnalyzeRequest(**body))
