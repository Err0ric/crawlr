from routers.analyze import parse_tagged_report, INVESTIGATION_PROMPT


def test_tagged_format():
    text = "<summary>\n- Identity – Jane Doe (GitHub)\n- Footprint – 6 accounts\n</summary>\n<report>\n## Case summary\nJane.\n## Investigative leads\n→ `\"jdoe\" site:linkedin.com`\n</report>"
    bullets, report = parse_tagged_report(text)
    assert bullets == ["Identity – Jane Doe (GitHub)", "Footprint – 6 accounts"]
    assert report.startswith("## Case summary") and "<report>" not in report


def test_truncated_report_still_renders():
    bullets, report = parse_tagged_report("<summary>\n- A – b\n</summary>\n<report>\n## Case summary\ncut off mid")
    assert bullets == ["A – b"] and report.endswith("cut off mid")


def test_legacy_json_and_raw_text_fallbacks():
    b, r = parse_tagged_report('```json\n{"short_summary": ["x"], "full_report": "## R"}\n```')
    assert b == ["x"] and r == "## R"
    b, r = parse_tagged_report("Just some prose the model wrote\nwith two lines")
    assert r.startswith("Just some prose") and b


def test_prompt_asks_for_investigation_sections_and_no_invention():
    for section in ("## Case summary", "## Identity assessment", "## Platform footprint", "## Exposure and risk", "## Investigative leads", "## Gaps and next pivots"):
        assert section in INVESTIGATION_PROMPT
    assert "Never invent" in INVESTIGATION_PROMPT
