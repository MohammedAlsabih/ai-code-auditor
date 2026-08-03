"""REAL-CORPUS-1B: the reviewer screen, driven by a real browser.

Everything in `test_real_corpus_review.py` reads the generated HTML as text.
That proves what the document SAYS; it cannot prove what it DOES. A form
that renders but does not save, a localStorage key that is computed before
the bundle is validated, a code block that pushes the page sideways on a
phone — all of those pass a string assertion and fail a reviewer.

So this file opens the real generated file in Chromium, at 1280 and at 375,
fills a Track A unit and a Track B unit, reloads to prove the answers
survived, exports, and checks that the browser made no network request of
any kind.

Playwright is a local-only dependency: it is not in the project's
requirements and CI skips this module cleanly rather than installing a
browser. `python -m pip install playwright && python -m playwright install
chromium` enables it.
"""
from __future__ import annotations

import json

import pytest

sync_api = pytest.importorskip(
    "playwright.sync_api",
    reason="playwright is a local-only dev dependency; run "
           "`pip install playwright && playwright install chromium`")

from tests.test_real_corpus_review import (  # noqa: E402
    _blind_packet,
    _bundle,
    _packets,
    _r3_packet_pair,
)
from tools.real_corpus_review import (  # noqa: E402
    ReviewError,
    build_bundle,
    check_issues,
    import_r3,
    render_r3_ui,
    render_ui,
)

VIEWPORTS = [pytest.param({"width": 1280, "height": 900}, id="desktop-1280"),
             pytest.param({"width": 375, "height": 812}, id="phone-375")]


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


def _page(browser, tmp_path, viewport, reviewer="R1"):
    """The real generated artefacts, on disk, opened as a file:// URL —
    the same way a reviewer will open them."""
    html = tmp_path / f"review_{reviewer}.html"
    html.write_text(render_ui(reviewer), encoding="utf-8")
    bundle = tmp_path / f"bundle_{reviewer}.json"
    bundle.write_text(json.dumps(_bundle(reviewer), indent=1, sort_keys=True),
                      encoding="utf-8")

    context = browser.new_context(viewport=viewport)
    page = context.new_page()
    requests: list[str] = []
    page.on("request", lambda r: requests.append(r.url))
    page.goto(html.as_uri())
    page.set_input_files("#file", str(bundle))
    page.wait_for_function("() => document.querySelector('#unit').innerHTML")
    return context, page, requests, bundle


def _answer_track_a(page):
    page.select_option('[data-f="label"]', "confirmed")
    page.select_option('[data-f="level"]', "error")
    page.select_option('[data-f="gate"]', "block")
    page.select_option('[data-f="actionability"]', "actionable")
    page.select_option('[data-f="evidence_sufficiency"]', "sufficient")
    page.fill('[data-f="reason"]', 'the line assigns a literal "secret"')


@pytest.mark.parametrize("viewport", VIEWPORTS)
def test_track_a_can_be_answered_and_survives_a_reload(browser, tmp_path,
                                                       viewport):
    context, page, requests, bundle = _page(browser, tmp_path, viewport)
    try:
        assert "Track A" in page.inner_text("#unit")
        _answer_track_a(page)
        assert "1/7 complete" in page.inner_text("#progress")

        page.reload()
        page.set_input_files("#file", str(bundle))
        page.wait_for_function(
            "() => document.querySelector('#progress').textContent"
            ".includes('1/7')")
        assert page.input_value('[data-f="reason"]') == \
            'the line assigns a literal "secret"'
        assert page.eval_on_selector('[data-f="label"]', "el => el.value") == \
            "confirmed"
        assert not requests_off_disk(requests)
    finally:
        context.close()


@pytest.mark.parametrize("viewport", VIEWPORTS)
def test_track_b_validates_an_issue_before_the_unit_counts(browser, tmp_path,
                                                           viewport):
    """The defect this closes: line/span/rule were checked only on import.
    A reviewer could reach a green "complete", export, and have the whole
    file refused with no way to tell which of 84 units was wrong."""
    context, page, requests, _ = _page(browser, tmp_path, viewport)
    try:
        for _ in range(4):                       # past the four Track A units
            page.click("#next")
        assert "Track B" in page.inner_text("#unit")

        page.click("#addissue")
        page.select_option('[data-f="outcome"]', "issues_found")
        page.fill('[data-i="0"][data-f="rule_id"]', "P001")
        page.fill('[data-i="0"][data-f="line"]', "9999")     # outside the unit
        page.fill('[data-i="0"][data-f="span"]', "105-115")
        page.fill('[data-i="0"][data-f="statement"]', "a literal credential")
        page.fill('[data-i="0"][data-f="evidence"]', "line 110 assigns it")
        page.select_option('[data-i="0"][data-f="level"]', "error")
        page.select_option('[data-i="0"][data-f="actionability"]', "actionable")

        assert "outside this unit" in page.inner_text("#unit")
        assert "0/7 complete" in page.inner_text("#progress")

        page.fill('[data-i="0"][data-f="line"]', "110")
        assert "outside this unit" not in page.inner_text("#unit")
        assert "1/7 complete" in page.inner_text("#progress")
        assert not requests_off_disk(requests)
    finally:
        context.close()


@pytest.mark.parametrize("viewport", VIEWPORTS)
def test_an_incomplete_export_is_named_a_draft_and_carries_the_identity(
        browser, tmp_path, viewport):
    context, page, requests, _ = _page(browser, tmp_path, viewport)
    try:
        _answer_track_a(page)
        with page.expect_download() as caught:
            page.click("#export")
        download = caught.value
        assert download.suggested_filename == "result_R1_DRAFT.json"

        saved = tmp_path / "exported.json"
        download.save_as(saved)
        result = json.loads(saved.read_text(encoding="utf-8"))
        bundle = _bundle("R1")
        assert result["protocol_version"] == bundle["protocol_version"]
        assert result["bundle_id"] == bundle["bundle_id"]
        assert result["track_digests"] == {
            t: bundle["tracks"][t]["digest"] for t in ("findings", "blind")}
        assert result["complete"] is False
        assert not requests_off_disk(requests)
    finally:
        context.close()


@pytest.mark.parametrize("viewport", VIEWPORTS)
def test_the_page_never_scrolls_sideways(browser, tmp_path, viewport):
    """Code is wide. It must scroll INSIDE its own block, not push the whole
    page — on a phone that makes the form unusable."""
    context, page, _, _ = _page(browser, tmp_path, viewport)
    try:
        for _ in range(5):                        # a Track B unit: real code
            page.click("#next")
        overflow = page.evaluate(
            "() => document.documentElement.scrollWidth - "
            "document.documentElement.clientWidth")
        assert overflow <= 0, f"the page scrolls sideways by {overflow}px"
    finally:
        context.close()


@pytest.mark.parametrize("viewport", VIEWPORTS)
def test_the_reviewer_screen_makes_no_network_request(browser, tmp_path,
                                                      viewport):
    context, page, requests, _ = _page(browser, tmp_path, viewport)
    try:
        _answer_track_a(page)
        page.click("#next")
        assert requests_off_disk(requests) == [], requests
    finally:
        context.close()


def test_a_bundle_from_the_other_reviewer_is_refused(browser, tmp_path):
    context, page, _, _ = _page(browser, tmp_path, VIEWPORTS[0].values[0])
    try:
        other = tmp_path / "bundle_R2.json"
        other.write_text(json.dumps(_bundle("R2")), encoding="utf-8")
        messages = []
        page.on("dialog", lambda d: (messages.append(d.message), d.dismiss()))
        page.set_input_files("#file", str(other))
        page.wait_for_function("() => true")
        assert any("belongs to R2" in m for m in messages), messages
    finally:
        context.close()


def test_a_second_bundle_starts_empty_in_a_real_browser(browser, tmp_path):
    """THE DEFECT, end to end. Same reviewer, same sample_ids, different
    material: revision 1 shared one localStorage key and showed the reviewer
    their earlier answer already filled in."""
    context, page, _, first = _page(browser, tmp_path, VIEWPORTS[0].values[0])
    try:
        _answer_track_a(page)
        assert "1/7 complete" in page.inner_text("#progress")

        packets = _packets("R1")
        packets["findings"][0]["claim"]["detail"] = "a different claim"
        second = tmp_path / "bundle_R1_second.json"
        second.write_text(json.dumps(build_bundle(packets, "R1")),
                          encoding="utf-8")

        page.set_input_files("#file", str(second))
        page.wait_for_function(
            "() => document.querySelector('#unit').innerHTML"
            ".includes('a different claim')")
        assert "0/7 complete" in page.inner_text("#progress")
        assert page.input_value('[data-f="reason"]') == ""

        # ...and the first bundle's answers were not destroyed either
        page.set_input_files("#file", str(first))
        page.wait_for_function(
            "() => document.querySelector('#progress').textContent"
            ".includes('1/7')")
    finally:
        context.close()


def requests_off_disk(urls: list[str]) -> list[str]:
    """Every request the page made that was not the local document itself."""
    return [u for u in urls if not u.startswith("file://")]


# ---- the load handler is all-or-nothing --------------------------------------------------------

def test_a_mispicked_file_never_rebinds_the_storage_key(browser, tmp_path):
    """THE DEFECT, end to end, with no hand-edited file.

    The tool's OWN exported result has no `instructions`, and it lands in the
    same folder as the bundle. The load handler used to replace BUNDLE, FLAT,
    KEY and answers BEFORE reading `instructions`, so picking the wrong file
    threw after the swap: the previous bundle's form stayed on screen, its
    listeners still live, now writing through the NEW key. One slip in the
    file picker and a judgement formed on one bundle's material was stored as
    an answer about another's — and the import cannot see it, because every
    id, digest and non-editable field is genuine."""
    context, page, _, bundle = _page(browser, tmp_path, VIEWPORTS[0].values[0])
    try:
        _answer_track_a(page)
        with page.expect_download() as caught:
            page.click("#export")
        exported = tmp_path / "result_R1_DRAFT.json"
        caught.value.save_as(exported)
        assert "instructions" not in json.loads(
            exported.read_text(encoding="utf-8"))

        before = page.evaluate("() => ({key: KEY, id: BUNDLE.bundle_id})")
        messages = []
        page.on("dialog", lambda d: (messages.append(d.message), d.dismiss()))
        page.set_input_files("#file", str(exported))
        page.wait_for_function("() => true")

        assert any("not a reviewer bundle" in m for m in messages), messages
        after = page.evaluate("() => ({key: KEY, id: BUNDLE.bundle_id})")
        assert after == before, "the screen and its storage key did not move"
        assert "1/7 complete" in page.inner_text("#progress")

        # ...and the answer that was already saved is still the right one
        page.reload()
        page.set_input_files("#file", str(bundle))
        page.wait_for_function(
            "() => document.querySelector('#progress').textContent"
            ".includes('1/7')")
        assert page.input_value('[data-f="reason"]') == \
            'the line assigns a literal "secret"'
    finally:
        context.close()


def test_a_bundle_with_an_empty_track_is_refused_before_anything_swaps(
        browser, tmp_path):
    context, page, _, _ = _page(browser, tmp_path, VIEWPORTS[0].values[0])
    try:
        hollow = _bundle("R1")
        hollow["tracks"]["findings"]["entries"] = []
        path = tmp_path / "hollow.json"
        path.write_text(json.dumps(hollow), encoding="utf-8")

        messages = []
        page.on("dialog", lambda d: (messages.append(d.message), d.dismiss()))
        page.set_input_files("#file", str(path))
        page.wait_for_function("() => true")
        assert any("no units" in m for m in messages), messages
        assert page.evaluate("() => FLAT.length") == 7
    finally:
        context.close()


# ---- the browser and the importer must reach the SAME verdict ----------------------------------

DIVERGENCE_CASES = [
    ("a leading space in the span", "span", " 105-115"),
    ("a trailing space in the span", "span", "105-115 "),
    ("a leading space in the line", "line", " 110"),
    ("the line typed as 110.0", "line", "110.0"),
    ("the line in exponent form", "line", "1.1e2"),
    ("the line in hex", "line", "0x6e"),
    ("a line outside the unit", "line", "9999"),
    ("a span that is not a span", "span", "not-a-span"),
    ("a rule that was never offered", "rule_id", "N999"),
]


@pytest.mark.parametrize("why, field, value", DIVERGENCE_CASES)
def test_the_browser_and_the_importer_agree_on_every_answer(browser, tmp_path,
                                                            why, field, value):
    """THE REQUIREMENT, stated as the equality it actually is. Either check
    alone can be right while the pair is wrong: what a reviewer needs is that
    a green "complete" and an accepted import never disagree. One stray space
    used to pass in the browser and fail at import, refusing all 204 units
    over something the screen showed as fine."""
    context, page, _, _ = _page(browser, tmp_path, viewport=VIEWPORTS[0].values[0])
    try:
        entry = _bundle("R1")["tracks"]["blind"]["entries"][0]
        answer = {"rule_id": "P001", "line": "110", "span": "105-115",
                  "statement": "a literal credential is assigned",
                  "evidence": "line 110 assigns a quoted secret",
                  "level": "error", "actionability": "actionable"}
        answer[field] = value

        js_ok = page.evaluate(
            "([e, i]) => issueProblem(e, i) === ''", [entry, answer])

        source = {"code_unit": entry["code_unit"],
                  "applicable_rules": entry["applicable_rules"]}
        try:
            check_issues("probe", [answer], source)
            py_ok = True
        except ReviewError:
            py_ok = False

        assert js_ok == py_ok, (
            f"{why}: the browser says complete={js_ok} and the importer says "
            f"acceptable={py_ok}")
        assert py_ok is False, f"{why} should be refused by both"
    finally:
        context.close()


def test_the_valid_answer_is_accepted_by_both(browser, tmp_path):
    """The equality above must not be satisfied by refusing everything."""
    context, page, _, _ = _page(browser, tmp_path, VIEWPORTS[0].values[0])
    try:
        entry = _bundle("R1")["tracks"]["blind"]["entries"][0]
        answer = {"rule_id": "P001", "line": "110", "span": "105-115",
                  "statement": "a literal credential is assigned",
                  "evidence": "line 110 assigns a quoted secret",
                  "level": "error", "actionability": "actionable"}
        assert page.evaluate("([e, i]) => issueProblem(e, i)",
                             [entry, answer]) == ""
        assert len(check_issues("probe", [answer],
                                {"code_unit": entry["code_unit"],
                                 "applicable_rules":
                                     entry["applicable_rules"]})) == 1
    finally:
        context.close()


def test_a_stray_space_never_reaches_a_green_complete(browser, tmp_path):
    """The same defect through the real form, not through page.evaluate."""
    context, page, _, _ = _page(browser, tmp_path, VIEWPORTS[0].values[0])
    try:
        for _ in range(4):
            page.click("#next")
        page.click("#addissue")
        page.select_option('[data-f="outcome"]', "issues_found")
        page.fill('[data-i="0"][data-f="rule_id"]', "P001")
        page.fill('[data-i="0"][data-f="line"]', "110")
        page.fill('[data-i="0"][data-f="span"]', " 105-115")
        page.fill('[data-i="0"][data-f="statement"]', "a literal credential")
        page.fill('[data-i="0"][data-f="evidence"]', "line 110 assigns it")
        page.select_option('[data-i="0"][data-f="level"]', "error")
        page.select_option('[data-i="0"][data-f="actionability"]', "actionable")

        assert "no spaces" in page.inner_text("#unit")
        assert "0/7 complete" in page.inner_text("#progress")
        page.fill('[data-i="0"][data-f="span"]', "105-115")
        assert "1/7 complete" in page.inner_text("#progress")
    finally:
        context.close()


# ---- localStorage failure is visible on the FIRST keystroke ------------------------------------

def test_a_broken_localstorage_is_reported_while_it_still_matters(browser,
                                                                  tmp_path):
    context, page, _, _ = _page(browser, tmp_path, VIEWPORTS[0].values[0])
    try:
        page.evaluate("""() => {
          Storage.prototype.setItem = function(){
            const e = new Error("quota"); e.name = "QuotaExceededError";
            throw e;
          };
        }""")
        page.fill('[data-f="reason"]', "x")
        warning = page.inner_text("#storagewarn")
        assert "NOT SAVED" in warning and "QuotaExceededError" in warning
        assert page.eval_on_selector(
            "#storagewarn", "el => getComputedStyle(el).display") != "none"
    finally:
        context.close()


# ---- R3 can arbitrate a Track B case ------------------------------------------------------------

def _r3_page(browser, tmp_path, packet, viewport=None):
    html = tmp_path / "arbitrate_R3.html"
    html.write_text(render_r3_ui(), encoding="utf-8")
    path = tmp_path / "r3_packet.json"
    path.write_text(json.dumps(packet, indent=1), encoding="utf-8")
    context = browser.new_context(viewport=viewport or VIEWPORTS[0].values[0])
    page = context.new_page()
    requests: list[str] = []
    page.on("request", lambda r: requests.append(r.url))
    page.goto(html.as_uri())
    page.set_input_files("#file", str(path))
    page.wait_for_function("() => PACKET !== null")
    return context, page, requests


def test_r3_can_record_an_issues_found_arbitration_that_imports(browser,
                                                                tmp_path):
    """THE DEFECT: the blind form offered an `outcome` dropdown and hard-coded
    `issues: []` into the export. `issues_found` with an empty list is
    refused, so the only blind arbitration the screen could produce that
    survived import was one denying every issue both reviewers had found."""
    packet = _blind_packet()
    context, page, requests = _r3_page(browser, tmp_path, packet)
    try:
        while page.evaluate("() => PACKET[idx].track") != "blind":
            page.click("#next")
        unit = page.evaluate("() => PACKET[idx].material.code_unit")

        page.select_option('[data-f="outcome"]', "issues_found")
        page.click("#addissue")
        page.fill('[data-i="0"][data-f="rule_id"]', "P001")
        page.fill('[data-i="0"][data-f="line"]', str(unit["start_line"] + 5))
        page.fill('[data-i="0"][data-f="span"]',
                  f'{unit["start_line"]}-{unit["end_line"]}')
        page.fill('[data-i="0"][data-f="statement"]', "R3 confirms it")
        page.fill('[data-i="0"][data-f="evidence"]', "the line is literal")
        page.select_option('[data-i="0"][data-f="level"]', "error")
        page.select_option('[data-i="0"][data-f="actionability"]', "actionable")
        page.fill('[data-f="reason"]', "A read the unit correctly")

        assert "1/" in page.inner_text("#progress")

        # decide the rest so the export is complete, then import it for real
        for _ in range(len(packet)):
            if not page.evaluate("() => decided(PACKET[idx])"):
                _decide_current_r3_case(page)
            if page.evaluate("() => idx") < len(packet) - 1:
                page.click("#next")
        with page.expect_download() as caught:
            page.click("#export")
        out = tmp_path / "r3_result.json"
        caught.value.save_as(out)

        accepted = import_r3(json.loads(out.read_text(encoding="utf-8")),
                             packet)
        assert accepted["state"] == "accepted"
        blind = [c for c in packet if c["track"] == "blind"][0]
        stored = accepted["resolved"][blind["sample_id"]]["final"]
        assert stored["outcome"] == "issues_found"
        assert len(stored["issues"]) == 1
        assert requests_off_disk(requests) == []
    finally:
        context.close()


def _decide_current_r3_case(page):
    track = page.evaluate("() => PACKET[idx].track")
    if track == "findings":
        page.select_option('[data-f="label"]', "confirmed")
        page.select_option('[data-f="level"]', "error")
        page.select_option('[data-f="gate"]', "block")
        page.select_option('[data-f="actionability"]', "actionable")
        page.select_option('[data-f="evidence_sufficiency"]', "sufficient")
    else:
        page.select_option('[data-f="outcome"]', "no_issue_observed")
    page.fill('[data-f="reason"]', "arbitrated on the material shown")


def test_the_r3_screen_shows_the_material_not_just_two_verdicts(browser,
                                                                tmp_path):
    packet = _r3_packet_pair()
    context, page, _ = _r3_page(browser, tmp_path, packet)
    try:
        while page.evaluate("() => PACKET[idx].track") != "findings":
            page.click("#next")
        shown = page.inner_text("#case")
        material = page.evaluate("() => PACKET[idx].material")
        assert material["claim"]["snippet"] in shown
        assert material["judged_on"]["source_window"] in shown
        assert "judgement A" in shown and "judgement B" in shown
        assert "R1" not in shown and "R2" not in shown
    finally:
        context.close()


def test_a_rebuilt_r3_packet_does_not_inherit_the_earlier_answers(browser,
                                                                  tmp_path):
    packet = _r3_packet_pair()
    context, page, _ = _r3_page(browser, tmp_path, packet)
    try:
        _decide_current_r3_case(page)
        assert "1/" in page.inner_text("#progress")

        # same length, same first sample_id, different material
        rebuilt = json.loads(json.dumps(packet))
        for case in rebuilt:
            if case["track"] == "findings":
                case["material"]["claim"]["detail"] = "a different claim"
        other = tmp_path / "rebuilt.json"
        other.write_text(json.dumps(rebuilt), encoding="utf-8")
        page.set_input_files("#file", str(other))
        page.wait_for_function(
            "() => document.querySelector('#progress').textContent"
            ".startsWith('0/')")
        assert page.input_value('[data-f="reason"]') == ""
    finally:
        context.close()


@pytest.mark.parametrize("viewport", VIEWPORTS)
def test_the_r3_screen_does_not_scroll_sideways(browser, tmp_path, viewport):
    packet = _blind_packet()
    context, page, _ = _r3_page(browser, tmp_path, packet, viewport)
    try:
        while page.evaluate("() => PACKET[idx].track") != "blind":
            page.click("#next")
        overflow = page.evaluate(
            "() => document.documentElement.scrollWidth - "
            "document.documentElement.clientWidth")
        assert overflow <= 0, f"the page scrolls sideways by {overflow}px"
    finally:
        context.close()
