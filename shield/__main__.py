"""Shield entry point: python -m shield opens the window."""

import argparse

from shield.core.config import detect_mode


def _open_window():
    # Imported here so that --info works even where tkinter is missing.
    from shield.ui.app import main as run_window

    run_window()


def main(argv=None, launch=_open_window, out=print):
    """This function opens the window, or prints the mode with --info."""
    parser = argparse.ArgumentParser(
        prog="shield", description="Shield: a local security helper."
    )
    parser.add_argument(
        "--info", action="store_true", help="print the detected mode and exit"
    )
    args = parser.parse_args(argv)

    if args.info:
        out(f"Detected mode: {detect_mode()}")
        return 0
    try:
        launch()
    except Exception as error:
        out(
            f"Could not open the window ({type(error).__name__}). "
            "Try: python -m shield --info"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())