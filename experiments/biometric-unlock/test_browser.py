#!/usr/bin/env python3
"""Real Chromium + virtual authenticator. Never reports physical biometric success."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parent


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=str(ROOT / "browser")))
thread = Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1100, "height": 850})
        origin = f"http://localhost:{server.server_port}"
        requests, errors = [], []
        page.on("request", lambda request: requests.append((request.method, request.url)))
        page.on("pageerror", lambda error: errors.append(error.name))
        page.goto(origin)
        expect(page.locator("#capability")).to_contain_text("WebAuthn is available")
        expect(page.get_by_role("button", name="Seal test data")).to_be_disabled()
        session = page.context.new_cdp_session(page)
        session.send("WebAuthn.enable")
        authenticator = session.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "ctap2Version": "ctap2_1", "transport": "internal",
            "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True,
            "automaticPresenceSimulation": True, "hasPrf": True,
        }})["authenticatorId"]
        page.get_by_role("button", name="Create test passkey").click()
        expect(page.locator("#result")).to_contain_text("PRF-enabled test credential created")
        page.get_by_role("button", name="Seal test data").click()
        expect(page.locator("#result")).to_contain_text("Test data sealed")
        page.get_by_role("button", name="Open test data").click()
        expect(page.locator("#result")).to_contain_text("Passed:")
        assert page.evaluate("localStorage.length === 0 && sessionStorage.length === 0")
        output = ROOT.parents[1] / "output" / "biometric-unlock"
        output.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(output / "desktop.png"))
        page.set_viewport_size({"width": 390, "height": 844})
        page.emulate_media(color_scheme="dark")
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.screenshot(path=str(output / "mobile.png"), full_page=True)
        session.send("WebAuthn.setAutomaticPresenceSimulation", {
            "authenticatorId": authenticator, "enabled": False,
        })
        page.get_by_role("button", name="Open test data").click()
        expect(page.locator("#result")).to_contain_text("Waiting")
        page.get_by_role("button", name="Reset / cancel").click()
        expect(page.locator("#result")).to_contain_text("Test state cleared")
        expect(page.get_by_role("button", name="Seal test data")).to_be_disabled()
        session.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": authenticator})
        session.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
            "hasUserVerification": True, "isUserVerified": True,
            "automaticPresenceSimulation": True, "hasPrf": False,
        }})
        page.get_by_role("button", name="Create test passkey").click()
        expect(page.locator("#result")).to_contain_text("No fallback key was used")
        expect(page.get_by_role("button", name="Seal test data")).to_be_disabled()
        assert not errors, errors
        allowed = {"/", "/style.css", "/ui.mjs", "/probe.mjs", "/wrapper.mjs", "/favicon.ico"}
        assert all(method == "GET" and url.removeprefix(origin) in allowed for method, url in requests)
        print(f"Chromium {browser.version}: virtual PRF roundtrip, unsupported PRF, cancellation, responsive layout and static-only requests passed; physical biometrics NOT tested.")
        browser.close()
finally:
    server.shutdown()
    server.server_close()
    thread.join()
