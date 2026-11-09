from __future__ import annotations

import argparse
import concurrent.futures
import html
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

LINK_PATTERN = re.compile(r"\]\s*\(\s*(<[^>]+>|[^\s)]+)")
HTML_LINK_PATTERN = re.compile(r"<a\b[^>]*\bhref\s*=\s*['\"]([^'\"]+)['\"]", re.I)
HEADING_PATTERN = re.compile(r"^\s{0,3}#{1,6}\s+(.+)$")
NAMED_ANCHOR_PATTERN = re.compile(r"<a\b[^>]*\b(?:id|name)\s*=\s*['\"]([^'\"]+)['\"]", re.I)
BADGE_PATTERN = re.compile(r"\[!\[[^\]]*\]\([^)]+\)\]\([^)]+\)")
MARKDOWN_LINK_PATTERN = re.compile(r"\[([^\]]+)\]\([^)]+\)")
RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}


@dataclass(frozen=True)
class Link:
    source: str
    line: int
    target: str


@dataclass(frozen=True)
class Result:
    source: str
    line: int
    target: str
    status: str
    detail: str


def extract_links(source: Path, root: Path) -> list[Link]:
    text = source.read_text(encoding="utf-8")
    links: list[Link] = []
    in_fence = False
    for line_number, line in enumerate(text.splitlines(), 1):
        if re.match(r"^\s{0,3}(`{3,}|~{3,})", line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        targets = [match.group(1) for match in LINK_PATTERN.finditer(line)]
        targets += [match.group(1) for match in HTML_LINK_PATTERN.finditer(line)]
        for target in targets:
            value = html.unescape(target.strip("<>"))
            if value:
                links.append(Link(source.relative_to(root).as_posix(), line_number, value))
    return links


def heading_anchors(content: str) -> set[str]:
    anchors: set[str] = set()
    duplicates: dict[str, int] = {}
    for line in content.splitlines():
        anchors.update(html.unescape(x) for x in NAMED_ANCHOR_PATTERN.findall(line))
        match = HEADING_PATTERN.match(line)
        if not match:
            continue
        title = BADGE_PATTERN.sub("", match.group(1))
        title = MARKDOWN_LINK_PATTERN.sub(r"\1", title)
        title = re.sub(r"<[^>]*>", "", title)
        title = re.sub(r"[\x60*_~]", "", title).casefold()
        slug = re.sub(r"[^\w -]", "", title).replace(" ", "-")
        if slug:
            number = duplicates.get(slug, 0)
            duplicates[slug] = number + 1
            anchors.add(f"{slug}-{number}" if number else slug)
    return anchors


def validate_local(link: Link, root: Path, cache: dict[Path, set[str]]) -> Result | None:
    parsed = urllib.parse.urlsplit(link.target)
    if parsed.scheme in ("mailto", "tel", "data"):
        return None
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        return Result(link.source, link.line, link.target, "broken", f"Unsupported scheme: {parsed.scheme}")
    if parsed.scheme in ("http", "https") or link.target.startswith("//"):
        return None
    path = urllib.parse.unquote(parsed.path)
    source = root / link.source
    destination = (root / path.lstrip("/")) if path.startswith("/") else (source.parent / path)
    destination = destination.resolve() if path else source.resolve()
    if not destination.is_relative_to(root):
        return Result(link.source, link.line, link.target, "broken", "Path escapes repository")
    if not destination.exists():
        return Result(link.source, link.line, link.target, "broken", "Target file does not exist")
    if parsed.fragment and destination.is_file() and destination.suffix.lower() in (".md", ".markdown"):
        if destination not in cache:
            cache[destination] = heading_anchors(destination.read_text(encoding="utf-8"))
        anchor = urllib.parse.unquote(parsed.fragment)
        if anchor not in cache[destination]:
            return Result(link.source, link.line, link.target, "broken", "Heading anchor does not exist")
    return None


def classify_http(status: int | None, error: str | None) -> tuple[str, str]:
    if status is not None and status < 400:
        return "ok", f"HTTP {status}"
    if status in (401, 403, 408, 425, 429) or (status is not None and status >= 500):
        return "inconclusive", f"HTTP {status}"
    if status is not None:
        return "broken", f"HTTP {status}"
    return "inconclusive", error or "No response"


def probe_url(url: str, timeout: float, retries: int) -> tuple[str, str]:
    last_status: int | None = None
    last_error: str | None = None
    for attempt in range(retries + 1):
        for method in ("HEAD", "GET"):
            request = urllib.request.Request(
                url,
                method=method,
                headers={"User-Agent": "awesome-honeypots-link-checker/1.0", "Accept": "*/*"},
            )
            try:
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    last_status = response.status
                    if last_status < 400:
                        return "ok", f"HTTP {last_status}"
            except urllib.error.HTTPError as error:
                last_status = error.code
                last_error = str(error)
                error.close()
            except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
                last_error = str(error)
                last_status = None
            if method == "HEAD" and last_status is not None and last_status < 400:
                break
        if attempt < retries and (last_status in RETRYABLE_STATUS or last_status is None):
            time.sleep(min(2.0, 0.5 * (attempt + 1)))
        else:
            break
    return classify_http(last_status, last_error)


def audit_links(
    links: list[Link], root: Path, mode: str, timeout: float, retries: int, workers: int
) -> tuple[list[Result], dict[str, int]]:
    findings: list[Result] = []
    counts = {"links": len(links), "local_checked": 0, "external_checked": 0, "ok": 0, "broken": 0, "inconclusive": 0}
    cache: dict[Path, set[str]] = {}
    urls: dict[str, list[Link]] = {}
    for link in links:
        parsed = urllib.parse.urlsplit(link.target)
        external = parsed.scheme in ("http", "https") or link.target.startswith("//")
        if external and mode in ("external", "all"):
            url = ("https:" + link.target if link.target.startswith("//") else link.target).split("#", 1)[0]
            urls.setdefault(url, []).append(link)
        elif not external and mode in ("local", "all"):
            if parsed.scheme in ("mailto", "tel", "data"):
                continue
            counts["local_checked"] += 1
            finding = validate_local(link, root, cache)
            if finding:
                findings.append(finding)
                counts["broken"] += 1
            else:
                counts["ok"] += 1
    if urls:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(probe_url, url, timeout, retries): url for url in urls}
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                try:
                    status, detail = future.result()
                except Exception as error:
                    status, detail = "inconclusive", str(error)
                counts["external_checked"] += 1
                counts[status] += 1
                if status != "ok":
                    for link in urls[url]:
                        findings.append(Result(link.source, link.line, link.target, status, detail))
    findings.sort(key=lambda item: (item.source, item.line, item.target))
    return findings, counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Markdown links in this repository.")
    parser.add_argument("files", nargs="*", default=["README.md", "README_CN.md"])
    parser.add_argument("--mode", choices=("local", "external", "all"), default="local")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--report-only", action="store_true")
    args = parser.parse_args(argv)
    if args.timeout <= 0 or args.retries < 0 or not 1 <= args.workers <= 32:
        parser.error("timeout must be positive, retries nonnegative, and workers between 1 and 32")
    root = Path(__file__).resolve().parent
    sources = [(root / name).resolve() for name in args.files]
    if any(not source.is_file() or not source.is_relative_to(root) for source in sources):
        parser.error("All input files must exist inside the repository")
    links = [link for source in sources for link in extract_links(source, root)]
    findings, counts = audit_links(links, root, args.mode, args.timeout, args.retries, args.workers)
    for finding in findings:
        print(f"{finding.source}:{finding.line}: {finding.status}: {finding.target} ({finding.detail})")
    print(
        f"Links: {counts['links']} | Local: {counts['local_checked']} | "
        f"External unique: {counts['external_checked']} | Broken: {counts['broken']} | "
        f"Inconclusive: {counts['inconclusive']}"
    )
    if args.json_out:
        args.json_out.write_text(
            json.dumps({"mode": args.mode, "counts": counts, "findings": [asdict(f) for f in findings]}, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    if args.summary:
        summary = [
            "## Link audit",
            "",
            f"- Scanned links: {counts['links']}",
            f"- Checked local links: {counts['local_checked']}",
            f"- Checked unique external URLs: {counts['external_checked']}",
            f"- Broken: {counts['broken']}",
            f"- Inconclusive: {counts['inconclusive']}",
            "",
            "Download the JSON artifact for individual URLs and source lines.",
        ]
        with args.summary.open("a", encoding="utf-8") as output:
            output.write("\n".join(summary) + "\n")
    return 1 if counts["broken"] and not args.report_only else 0


if __name__ == "__main__":
    sys.exit(main())
