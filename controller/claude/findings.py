"""Finding file writer with slugification, sequencing, and deduplication."""

import os
import re


def slugify(text: str) -> str:
    """Convert text to a URL-safe slug."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[-\s]+", "-", text)
    return text.strip("-")


def extract_title(finding_text: str) -> str:
    """Extract the title from a structured finding report."""
    for line in finding_text.splitlines():
        line = line.strip()
        # "Title: ..." or "**Title**: ..." or "**Title:** ..."
        lower = line.lower()
        if lower.startswith("title:"):
            return line.split(":", 1)[1].strip().strip("*")
        if lower.startswith("**title**:") or lower.startswith("**title:**"):
            return line.split(":", 1)[1].strip().strip("*").strip()
        if line.startswith("#") and not line.startswith("####"):
            return line.lstrip("#").strip()
    # Fallback: first non-empty, non-heading line
    for line in finding_text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("---"):
            return line[:60]
    return "untitled"


def extract_endpoint(finding_text: str) -> str | None:
    """Extract the affected endpoint from a structured finding report."""
    for line in finding_text.splitlines():
        line = line.strip()
        lower = line.lower()
        if lower.startswith("affected endpoint") or lower.startswith("**affected endpoint"):
            _, _, value = line.partition(":")
            value = value.strip().strip("*").strip()
            if value:
                return value
    return None


def extract_severity(finding_text: str) -> str | None:
    """Extract the severity from a structured finding report."""
    for line in finding_text.splitlines():
        line = line.strip()
        lower = line.lower()
        if lower.startswith("severity:") or lower.startswith("**severity"):
            _, _, value = line.partition(":")
            value = value.strip().strip("*").strip().lower()
            if value:
                return value
    return None


def _titles_similar(a: str, b: str) -> bool:
    """True if slugified titles match, one contains the other, or >80% word overlap."""
    slug_a = slugify(a)
    slug_b = slugify(b)
    if slug_a == slug_b:
        return True
    if slug_a in slug_b or slug_b in slug_a:
        return True
    words_a = set(slug_a.split("-"))
    words_b = set(slug_b.split("-"))
    if not words_a or not words_b:
        return False
    overlap = len(words_a & words_b)
    total = max(len(words_a), len(words_b))
    return overlap / total > 0.8


class FindingWriter:
    """Manages writing finding reports to sequenced markdown files."""

    def __init__(self, findings_dir: str):
        self.findings_dir = findings_dir
        self.count = 0
        self.paths: list[str] = []
        self._index: list[dict] = []

    def is_duplicate(self, finding_text: str) -> bool:
        """True if this finding is a duplicate of an already-written finding."""
        title = extract_title(finding_text)
        title_slug = slugify(title)
        endpoint = extract_endpoint(finding_text)

        for entry in self._index:
            # Exact slug match
            if title_slug == entry["title_slug"]:
                return True
            # Same endpoint + similar title
            if endpoint and entry["endpoint"] and endpoint == entry["endpoint"]:
                if _titles_similar(title, entry["title"]):
                    return True
        return False

    def summary_for_orchestrator(self) -> str:
        """Compact numbered summary of findings filed so far."""
        if not self._index:
            return "No findings filed yet."
        lines = []
        for i, entry in enumerate(self._index, 1):
            sev = entry["severity"] or "unknown"
            endpoint = entry["endpoint"] or "N/A"
            lines.append(f"{i}. [{sev}] {entry['title']} — {endpoint}")
        return "**Findings filed so far:**\n" + "\n".join(lines)

    def write(self, finding_text: str) -> str:
        """Write a finding to a markdown file. Returns the file path."""
        os.makedirs(self.findings_dir, exist_ok=True)
        self.count += 1

        title = extract_title(finding_text)
        slug = slugify(title)
        if not slug:
            slug = "untitled"
        if len(slug) > 60:
            slug = slug[:60].rstrip("-")

        filename = f"finding-{self.count:02d}-{slug}.md"
        filepath = os.path.join(self.findings_dir, filename)

        with open(filepath, "w") as f:
            f.write(finding_text)
            if not finding_text.endswith("\n"):
                f.write("\n")

        self.paths.append(filepath)
        self._index.append({
            "title": title,
            "title_slug": slugify(title),
            "endpoint": extract_endpoint(finding_text),
            "severity": extract_severity(finding_text),
            "path": filepath,
        })
        return filepath
