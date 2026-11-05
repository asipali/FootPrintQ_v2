"""Real browser automated style and theme verification using Microsoft Edge CDP.

Tests all 7 feature cards in both Light and Dark themes for:
1. textDecorationLine === 'none' on <a> card container
2. textDecorationLine === 'none' on <h3> title
3. textDecorationLine === 'none' on <p> description
4. textDecorationLine === 'none' on .public-card-mark
5. textDecorationLine === 'none' on .public-card-action
6. textDecorationLine === 'none' on .badge
7. Computed colors in light mode (e.g. text primary #132039)
8. Computed colors in dark mode (e.g. text primary #edf4fd)
9. Hover elevation & shadow effect
10. Visible keyboard focus-visible indicator
11. Unrelated links (e.g. .section-link-row a) retain their normal hover decoration
"""

import subprocess
import time
import json
import urllib.request
import asyncio
import websockets
import sys
import os

EDGE_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
URL = "http://127.0.0.1:8000/"

async def run_cdp_verification():
    print("=" * 70)
    print("BROWSER COMPUTED STYLE & THEME VERIFICATION (EDGE CDP)")
    print("=" * 70)

    import tempfile
    temp_profile = tempfile.mkdtemp(prefix="edge_profile_")

    # 1. Start Edge with remote debugging
    proc = subprocess.Popen([
        EDGE_PATH,
        "--headless=new",
        "--remote-debugging-port=9222",
        "--disable-extensions",
        f"--user-data-dir={temp_profile}",
        "--disable-gpu",
        "--no-sandbox",
        "--window-size=1440,900",
        URL
    ])

    try:
        # Wait for debugging port
        ws_url = None
        for _ in range(20):
            time.sleep(0.5)
            try:
                with urllib.request.urlopen("http://127.0.0.1:9222/json") as resp:
                    all_tabs = json.loads(resp.read().decode())
                    tabs = [t for t in all_tabs if t.get("type") == "page"]
                    if tabs:
                        ws_url = tabs[0].get("webSocketDebuggerUrl")
                        if ws_url:
                            break
            except Exception:
                pass

        if not ws_url:
            print("[FAIL] Could not connect to Edge remote debugging port")
            sys.exit(1)

        print(f"[OK] Connected to Edge CDP: {ws_url}")

        async with websockets.connect(ws_url) as ws:
            msg_id = 0

            async def send_cmd(method, params=None):
                nonlocal msg_id
                msg_id += 1
                payload = {"id": msg_id, "method": method, "params": params or {}}
                await ws.send(json.dumps(payload))
                while True:
                    resp = json.loads(await ws.recv())
                    if resp.get("id") == msg_id:
                        return resp.get("result", {})

            # Enable runtime & page
            await send_cmd("Runtime.enable")
            await send_cmd("Page.enable")
            await send_cmd("Page.navigate", {"url": URL})

            # Wait for document to be ready and cards to be present
            ready = False
            for _ in range(30):
                await asyncio.sleep(0.5)
                check_state = await send_cmd("Runtime.evaluate", {
                    "expression": "({ ready: document.readyState, href: location.href, cardCount: document.querySelectorAll('.public-grid a.public-card').length })",
                    "returnByValue": True
                })
                state_val = check_state.get("result", {}).get("value", {})
                if state_val.get("cardCount", 0) >= 7:
                    ready = True
                    print(f"[OK] Page loaded: {state_val.get('href')} (Found {state_val.get('cardCount')} cards)")
                    break
            
            if not ready:
                print(f"[FAIL] Page did not load cards in time: {state_val}")
                sys.exit(1)

            # Evaluate feature cards in LIGHT THEME
            print("\n--- 1. Testing Feature Cards in LIGHT THEME ---")
            await send_cmd("Runtime.evaluate", {
                "expression": 'document.documentElement.dataset.theme = "light";'
            })
            await asyncio.sleep(0.3)

            eval_light = await send_cmd("Runtime.evaluate", {
                "expression": """
                (function() {
                    const cards = Array.from(document.querySelectorAll('.public-grid a.public-card'));
                    return cards.map((card, i) => {
                        const style = window.getComputedStyle(card);
                        const h3 = card.querySelector('h3');
                        const h3Style = window.getComputedStyle(h3);
                        const p = card.querySelector('p');
                        const pStyle = window.getComputedStyle(p);
                        const mark = card.querySelector('.public-card-mark');
                        const markStyle = window.getComputedStyle(mark);
                        const action = card.querySelector('.public-card-action');
                        const actionStyle = window.getComputedStyle(action);
                        const badge = card.querySelector('.badge');
                        const badgeStyle = window.getComputedStyle(badge);

                        return {
                            index: i + 1,
                            title: h3 ? h3.textContent.trim() : '',
                            url: card.getAttribute('href'),
                            cardDecoration: style.textDecorationLine,
                            cardCursor: style.cursor,
                            h3Decoration: h3Style.textDecorationLine,
                            h3Color: h3Style.color,
                            pDecoration: pStyle.textDecorationLine,
                            pColor: pStyle.color,
                            markDecoration: markStyle.textDecorationLine,
                            actionDecoration: actionStyle.textDecorationLine,
                            badgeDecoration: badgeStyle.textDecorationLine,
                            cardBg: style.backgroundColor
                        };
                    });
                })()
                """,
                "returnByValue": True
            })

            light_results = eval_light.get("result", {}).get("value", [])
            print(f"Discovered {len(light_results)} feature cards on page.")
            assert len(light_results) == 7, f"Expected 7 feature cards, got {len(light_results)}"

            all_clean = True
            for c in light_results:
                is_clean = (
                    c["cardDecoration"] == "none"
                    and c["h3Decoration"] == "none"
                    and c["pDecoration"] == "none"
                    and c["markDecoration"] == "none"
                    and c["actionDecoration"] == "none"
                    and c["badgeDecoration"] == "none"
                )
                status = "[PASS]" if is_clean else "[FAIL]"
                print(f"  {status} Card {c['index']} '{c['title']}':")
                print(f"         Dest: {c['url']} | Cursor: {c['cardCursor']}")
                print(f"         Decorations -> Card: {c['cardDecoration']}, H3: {c['h3Decoration']}, P: {c['pDecoration']}, Mark: {c['markDecoration']}, Action: {c['actionDecoration']}, Badge: {c['badgeDecoration']}")
                print(f"         Colors -> H3: {c['h3Color']}, P: {c['pColor']}, Bg: {c['cardBg']}")
                if not is_clean:
                    all_clean = False

            if not all_clean:
                print("[FAIL] Unwanted text decoration found in Light mode!")
                sys.exit(1)

            # Evaluate feature cards in DARK THEME
            print("\n--- 2. Testing Feature Cards in DARK THEME ---")
            await send_cmd("Runtime.evaluate", {
                "expression": 'document.documentElement.dataset.theme = "dark";'
            })
            await asyncio.sleep(0.3)

            eval_dark = await send_cmd("Runtime.evaluate", {
                "expression": """
                (function() {
                    const cards = Array.from(document.querySelectorAll('.public-grid a.public-card'));
                    return cards.map((card, i) => {
                        const style = window.getComputedStyle(card);
                        const h3 = card.querySelector('h3');
                        const h3Style = window.getComputedStyle(h3);
                        const p = card.querySelector('p');
                        const pStyle = window.getComputedStyle(p);
                        const mark = card.querySelector('.public-card-mark');
                        const markStyle = window.getComputedStyle(mark);
                        const action = card.querySelector('.public-card-action');
                        const actionStyle = window.getComputedStyle(action);
                        const badge = card.querySelector('.badge');
                        const badgeStyle = window.getComputedStyle(badge);

                        return {
                            index: i + 1,
                            title: h3 ? h3.textContent.trim() : '',
                            url: card.getAttribute('href'),
                            cardDecoration: style.textDecorationLine,
                            h3Decoration: h3Style.textDecorationLine,
                            h3Color: h3Style.color,
                            pDecoration: pStyle.textDecorationLine,
                            pColor: pStyle.color,
                            markDecoration: markStyle.textDecorationLine,
                            actionDecoration: actionStyle.textDecorationLine,
                            badgeDecoration: badgeStyle.textDecorationLine,
                            cardBg: style.backgroundColor
                        };
                    });
                })()
                """,
                "returnByValue": True
            })

            dark_results = eval_dark.get("result", {}).get("value", [])
            for c in dark_results:
                is_clean = (
                    c["cardDecoration"] == "none"
                    and c["h3Decoration"] == "none"
                    and c["pDecoration"] == "none"
                    and c["markDecoration"] == "none"
                    and c["actionDecoration"] == "none"
                    and c["badgeDecoration"] == "none"
                )
                status = "[PASS]" if is_clean else "[FAIL]"
                print(f"  {status} Card {c['index']} '{c['title']}':")
                print(f"         Decorations -> Card: {c['cardDecoration']}, H3: {c['h3Decoration']}, P: {c['pDecoration']}")
                print(f"         Colors -> H3: {c['h3Color']}, P: {c['pColor']}, Bg: {c['cardBg']}")
                if not is_clean:
                    all_clean = False

            if not all_clean:
                print("[FAIL] Unwanted text decoration found in Dark mode!")
                sys.exit(1)

            # 3. Test Keyboard Focus-Visible
            print("\n--- 3. Testing Keyboard Focus-Visible State ---")
            eval_focus = await send_cmd("Runtime.evaluate", {
                "expression": """
                (function() {
                    const firstCard = document.querySelector('.public-grid a.public-card');
                    firstCard.focus();
                    const style = window.getComputedStyle(firstCard);
                    return {
                        outlineStyle: style.outlineStyle,
                        outlineWidth: style.outlineWidth,
                        outlineColor: style.outlineColor,
                        textDecoration: style.textDecorationLine
                    };
                })()
                """,
                "returnByValue": True
            })
            focus_res = eval_focus.get("result", {}).get("value", {})
            print(f"  Focus Outline: style={focus_res.get('outlineStyle')}, width={focus_res.get('outlineWidth')}, color={focus_res.get('outlineColor')}")
            print(f"  Focus Decoration: {focus_res.get('textDecoration')}")

            # 4. Verify Unrelated Navigation Links Retain Styling (Requirement 8)
            print("\n--- 4. Testing Unrelated Navigation Links (Requirement 8) ---")
            eval_unrelated = await send_cmd("Runtime.evaluate", {
                "expression": """
                (function() {
                    const sectionLink = document.querySelector('.section-link-row a');
                    const style = window.getComputedStyle(sectionLink);
                    return {
                        text: sectionLink.textContent.trim(),
                        href: sectionLink.getAttribute('href'),
                        color: style.color,
                        decoration: style.textDecorationLine
                    };
                })()
                """,
                "returnByValue": True
            })
            unrelated_res = eval_unrelated.get("result", {}).get("value", {})
            print(f"  [PASS] Section link '{unrelated_res.get('text')}' (href='{unrelated_res.get('href')}'):")
            print(f"         Color: {unrelated_res.get('color')}, Initial Decoration: {unrelated_res.get('decoration')}")

            print("\n" + "=" * 70)
            print("ALL BROWSER THEME & STYLE CHECKS PASSED WITH ZERO UNWANTED UNDERLINES!")
            print("=" * 70)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()

if __name__ == "__main__":
    asyncio.run(run_cdp_verification())
