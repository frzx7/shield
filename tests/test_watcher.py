from shield.modules.dlp.watcher import ClipboardWatcher

SECRET = "AKIAIOSFODNN7EXAMPLE"


def make_watcher(texts):
    """Build a watcher whose 'clipboard' returns the given texts one by one."""
    received = []
    items = iter(texts)
    watcher = ClipboardWatcher(lambda: next(items), received.append)
    return watcher, received


def test_reports_secret_once_when_clipboard_unchanged():
    watcher, received = make_watcher([SECRET, SECRET])
    watcher.check_once()
    watcher.check_once()
    assert len(received) == 1


def test_clean_text_is_ignored():
    watcher, received = make_watcher(["hello world"])
    watcher.check_once()
    assert received == []


def test_empty_clipboard_is_ignored():
    watcher, received = make_watcher([None])
    watcher.check_once()
    assert received == []


def test_secret_is_reported_again_after_clipboard_changes():
    watcher, received = make_watcher([SECRET, "hello", SECRET])
    watcher.check_once()
    watcher.check_once()
    watcher.check_once()
    assert len(received) == 2