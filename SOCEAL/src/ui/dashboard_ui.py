"""
SOCeal - Project VALE
Dashboard UI: Launch the dashboard in a browser or native WebView2 window.
"""

import logging
import webbrowser

logger = logging.getLogger('soceal.ui.dashboard')


def launch_browser(url):
    """Open the dashboard in the default web browser."""
    try:
        webbrowser.open(url)
        logger.info("Opened dashboard in browser: %s", url)
    except Exception as e:
        logger.error("Failed to open browser: %s", e)


def launch_webview(url, title=None, safe_mode=True, on_close=None):
    """
    Open the dashboard in a native WebView2 window (pywebview).
    Falls back to browser if pywebview is not available.

    Args:
        url: Dashboard URL.
        title: Window title (auto-generated if None).
        safe_mode: Current mode for title display.
        on_close: Callback function when window is closed.
    """
    mode_tag = "[SAFE]" if safe_mode else "[ACTIVE]"
    title = title or f"SOCeal \u2013 Project VALE {mode_tag}"

    try:
        import webview
        logger.info("Launching native WebView2 window: %s", title)

        window = webview.create_window(title, url, width=1400, height=900, resizable=True)

        if on_close:
            try:
                window.events.closing += lambda: on_close()
            except Exception:
                # Older pywebview versions may not support events
                pass

        webview.start()  # Blocks until window is closed

        # Window closed -- trigger callback if not already done via event
        if on_close:
            try:
                on_close()
            except Exception:
                pass

    except ImportError:
        logger.info("pywebview not available \u2014 falling back to browser")
        launch_browser(url)
    except Exception as e:
        logger.error("WebView failed: %s \u2014 falling back to browser", e)
        launch_browser(url)
