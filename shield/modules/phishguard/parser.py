"""PhishGuard email parser.
 
This module turns a raw .eml file into a ParsedEmail: a plain data container
that the rules read. The parser only reads text. It never opens a link and
never saves or runs an attachment.
"""
 
import re
from dataclasses import dataclass, field
from email import message_from_bytes, policy
from html.parser import HTMLParser
from pathlib import Path
 
 
@dataclass
class ParsedEmail:
    """This class holds everything the rules need to know about one email."""
 
    from_addr: str = ""
    reply_to: str = ""
    subject: str = ""
    body_text: str = ""
    body_html: str = ""
    links: list[tuple[str, str]] = field(default_factory=list)  # (visible_text, href)
    attachments: list[str] = field(default_factory=list)  # file names only
    auth_results: str = ""
 
 
# This pattern finds plain-text URLs inside a message body.
URL_PATTERN = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
 
 
class _HtmlScanner(HTMLParser):
    """This class walks through HTML once and collects links and visible text."""
 
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.text_parts: list[str] = []
        self._href = None  # href of the <a> tag that is currently open
        self._link_text: list[str] = []
        self._skip_depth = 0  # greater than 0 while inside <script> or <style>
 
    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip_depth += 1
        elif tag == "a":
            href = dict(attrs).get("href")
            if href:
                self._href = href.strip()
                self._link_text = []
        elif tag in ("br", "p", "div", "tr", "li"):
            # This branch keeps line breaks so that words do not glue together.
            self.text_parts.append("\n")
 
    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "a":
            self.flush_link()
 
    def handle_data(self, data):
        if self._skip_depth:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._link_text.append(data)
 
    def flush_link(self):
        """This method stores the open link (if any) and closes it."""
        if self._href is not None:
            visible = " ".join("".join(self._link_text).split())
            self.links.append((visible, self._href))
            self._href = None
 
 
def _scan_html(html):
    """This function returns (links, visible_text) for an HTML string."""
    scanner = _HtmlScanner()
    scanner.feed(html)
    scanner.close()
    scanner.flush_link()  # This call keeps a link whose </a> tag is missing.
    raw_text = "".join(scanner.text_parts)
    lines = [" ".join(line.split()) for line in raw_text.splitlines()]
    return scanner.links, "\n".join(line for line in lines if line)
 
 
def _read_raw(source):
    """This function turns a Path, a file-path string, raw text or bytes into bytes."""
    if isinstance(source, bytes):
        return source
    if isinstance(source, Path):
        return source.read_bytes()
    if isinstance(source, str):
        # This block treats a short single-line string as a possible file path.
        if "\n" not in source and len(source) < 1000:
            try:
                path = Path(source)
                if path.is_file():
                    return path.read_bytes()
            except OSError:
                pass
        return source.encode("utf-8")
    raise TypeError("parse_eml expects a Path, str or bytes")
 
 
def _header(message, name):
    """This function returns a header as a clean string ("" when missing)."""
    return str(message.get(name, "") or "").strip()
 
 
def _part_text(part):
    """This function returns the decoded text of a message part ("" for None)."""
    if part is None:
        return ""
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError, ValueError):
        # This block handles unknown or broken charsets without crashing.
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")
 
 
def parse_eml(source) -> ParsedEmail:
    """This function parses an .eml file path, raw email text, or bytes."""
    message = message_from_bytes(_read_raw(source), policy=policy.default)
 
    # This block reads the plain-text and HTML bodies.
    body_text = _part_text(message.get_body(preferencelist=("plain",)))
    body_html = _part_text(message.get_body(preferencelist=("html",)))
 
    # This block collects links from the HTML (visible text + real href).
    links = []
    html_text = ""
    if body_html:
        links, html_text = _scan_html(body_html)
 
    # This block adds plain-text URLs. Their visible text equals the URL itself.
    for url in URL_PATTERN.findall(body_text):
        links.append((url.rstrip(".,;:!?"), url.rstrip(".,;:!?")))
 
    # This block fills body_text from the HTML for HTML-only emails, so that
    # the urgency rule always has text to read.
    if not body_text.strip() and html_text:
        body_text = html_text
 
    # This block lists attachment file names (the content is never touched).
    attachments = []
    for part in message.walk():
        name = part.get_filename()
        if name:
            attachments.append(name)
 
    # This block joins every Authentication-Results header into one string.
    auth_results = "; ".join(
        str(value) for value in message.get_all("Authentication-Results", [])
    )
 
    return ParsedEmail(
        from_addr=_header(message, "From"),
        reply_to=_header(message, "Reply-To"),
        subject=_header(message, "Subject"),
        body_text=body_text,
        body_html=body_html,
        links=list(dict.fromkeys(links)),
        attachments=attachments,
        auth_results=auth_results,
    )
 