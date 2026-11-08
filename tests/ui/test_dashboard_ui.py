"""Browser test of the dashboard against a RUNNING backend (opt-in).

    IDS_UI_URL=http://127.0.0.1:8000 python -m pytest tests/ui -v      (needs: pip install playwright)

Opens every page, fails on JavaScript errors or failed (5xx) API calls, checks every
page renders its content (not a loading spinner), exercises filters, the confirmation
dialog, form validation, and takes a screenshot of each page into tests/ui/screens/.
Mutating buttons that change the cluster are not clicked except the decoy-free ones
(labelled check, deception cycle) so the test is safe to run on a live lab.
"""
import os
from pathlib import Path

import pytest

URL = os.environ.get("IDS_UI_URL")
pytestmark = pytest.mark.skipif(not URL, reason="set IDS_UI_URL to a running dashboard")
PAGES = ["overview", "traffic", "threats", "window", "lab", "deception", "k8s", "model", "system", "scorer"]
SHOTS = Path(__file__).parent / "screens"


@pytest.fixture(scope="module")
def page():
    pw = pytest.importorskip("playwright.sync_api")
    with pw.sync_playwright() as p:
        exe = os.environ.get("IDS_CHROMIUM")  # e.g. a preinstalled Chromium
        b = p.chromium.launch(**({"executable_path": exe} if exe else {}))
        pg = b.new_page(viewport={"width": 1440, "height": 900})
        pg.errors, pg.bad = [], []
        pg.on("pageerror", lambda e: pg.errors.append(str(e)))
        pg.on("console", lambda m: m.type == "error" and pg.errors.append(m.text))
        pg.on("response", lambda r: "/api/" in r.url and r.status >= 500 and pg.bad.append(f"{r.status} {r.url}"))
        pg.goto(URL + "/#overview")
        pg.wait_for_timeout(2500)
        yield pg
        b.close()


@pytest.mark.parametrize("name", PAGES)
def test_every_nav_item_opens_its_page(page, name):
    page.click(f'nav button[data-page="{name}"]')
    page.wait_for_timeout(3500 if name in ("k8s", "lab", "system") else 2000)
    sec = page.locator(f"#p-{name}")
    assert sec.is_visible()
    assert "on" in (page.locator(f'nav button[data-page="{name}"]').get_attribute("class") or "")
    assert page.locator(f"#p-{name} .loading").count() == 0 or name == "scorer", f"{name} still loading"
    assert page.locator(f"#p-{name} .page-err").count() == 0, page.locator(f"#p-{name} .page-err").inner_text()
    SHOTS.mkdir(exist_ok=True)
    page.screenshot(path=str(SHOTS / f"{name}.png"), full_page=True)
    assert not page.errors, page.errors
    assert not page.bad, page.bad


def test_filters_and_forms(page):
    page.click('nav button[data-page="traffic"]')
    page.select_option("#flMal", "false")
    page.wait_for_timeout(1500)
    page.fill("#flSrc", "not an ip!")
    page.press("#flSrc", "Enter")
    page.dispatch_event("#flSrc", "change")
    page.wait_for_timeout(800)
    assert "Source IP" in page.locator("#flowsTable").inner_text()
    page.fill("#flSrc", "")
    page.dispatch_event("#flSrc", "change")
    page.click('nav button[data-page="lab"]')
    page.wait_for_timeout(2500)
    page.fill("#labCount", "0")
    page.click("#labLaunch")
    page.wait_for_timeout(500)
    assert "whole number" in page.locator("#labForm").inner_text()
    page.fill("#labCount", "300")
    page.select_option("#labScenario", "brute_force")
    assert page.locator("#labTarget").input_value() == "grafana"
    assert not page.errors, page.errors


def test_confirmation_dialog_cancel_does_nothing(page):
    page.click('nav button[data-page="deception"]')
    page.wait_for_timeout(2500)
    if page.locator("#decDisable").is_enabled():
        page.click("#decDisable")
        assert page.locator("#confirmDlg").is_visible()
        page.click("#cfNo")
        page.wait_for_timeout(500)
        assert page.locator("#decDisable").is_enabled()


def test_labelled_check_and_cycle_buttons(page):
    page.click('nav button[data-page="threats"]')
    page.wait_for_timeout(1500)
    page.click("#evalBtn")
    page.wait_for_selector("#evalOut .kpi", timeout=60000)
    assert "Accuracy" in page.locator("#evalOut").inner_text()
    page.click('nav button[data-page="deception"]')
    page.wait_for_timeout(1500)
    page.click("#decCycle")
    page.wait_for_selector(".toast", timeout=20000)
    assert not page.bad, page.bad


def test_mobile_layout_has_no_horizontal_scroll(page):
    page.set_viewport_size({"width": 390, "height": 844})
    for name in ("overview", "deception"):
        page.goto(URL + "/#" + name)
        page.wait_for_timeout(2500)
        w = page.evaluate("document.documentElement.scrollWidth")
        assert w <= 392, (name, w)
        page.screenshot(path=str(SHOTS / f"mobile_{name}.png"), full_page=False)
    page.set_viewport_size({"width": 1440, "height": 900})
