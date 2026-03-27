"""
SOCeal – Project VALE
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


def launch_webview(url, title="SOCeal – Project VALE"):
    """
    Open the dashboard in a native WebView2 window (pywebview).
    Falls back to browser if pywebview is not available.
    """
    try:
        import webview
        logger.info("Launching native WebView2 window: %s", title)
        webview.create_window(title, url, width=1400, height=900, resizable=True)
        webview.start()  # This blocks until window is closed
    except ImportError:
        logger.info("pywebview not available — falling back to browser")
        launch_browser(url)
    except Exception as e:
        logger.error("WebView failed: %s — falling back to browser", e)
        launch_browser(url)
