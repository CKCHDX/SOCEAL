"""
SOCeal – Project VALE
Dashboard UI launcher — opens the SOC dashboard in a browser or native WebView2 window.
"""

import logging
import webbrowser

logger = logging.getLogger('soceal.ui')


def launch_browser(url):
    """Open the SOCeal dashboard in the default web browser."""
    try:
        webbrowser.open(url)
        logger.info("Dashboard opened in browser: %s", url)
    except Exception as e:
        logger.error("Failed to open browser: %s", e)


def launch_webview(url):
    """
    Open the SOCeal dashboard in a native WebView2 window via pywebview.
    Falls back to browser if pywebview is unavailable.
    """
    try:
        import webview
        webview.create_window(
            title='SOCeal – Project VALE',
            url=url,
            width=1400,
            height=880,
            resizable=True,
            frameless=False,
            on_top=False,
            background_color='#020c14',
        )
        webview.start(debug=False)
        logger.info("Dashboard opened in WebView2 window: %s", url)
    except ImportError:
        logger.warning("pywebview not available — falling back to browser")
        launch_browser(url)
    except Exception as e:
        logger.error("WebView failed: %s — falling back to browser", e)
        launch_browser(url)
