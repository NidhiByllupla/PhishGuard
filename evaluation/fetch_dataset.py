"""Build a balanced URL evaluation dataset from public research/security feeds.

Sources:
- PhishTank verified-online phishing feed
- Tranco top-sites ranking

Safety:
URLs are downloaded as text records only. This script does not visit any URL
contained in either dataset.

Usage:
    python -m evaluation.fetch_dataset
    python -m evaluation.fetch_dataset --phishing 250 --legitimate 250

Optional:
    Set PHISHTANK_APP_KEY to use your PhishTank application key.
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import random
import urllib.request
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DEFAULT_OUTPUT = DATA_DIR / "evaluation_dataset.csv"

PHISHTANK_BASE = "http://data.phishtank.com/data"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

USER_AGENT = "PhishGuard-evaluation/NidhiByllupla"


def _download(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def _phishtank_url() -> str:
    app_key = os.getenv("PHISHTANK_APP_KEY", "").strip()
    if app_key:
        return f"{PHISHTANK_BASE}/{app_key}/online-valid.csv"
    return f"{PHISHTANK_BASE}/online-valid.csv"


def fetch_phishing_rows(limit: int, seed: int):
    raw = _download(_phishtank_url())
    text = raw.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))

    candidates = []
    for row in reader:
        url = (row.get("url") or "").strip()
        verified = (row.get("verified") or "").lower()
        online = (row.get("online") or "").lower()

        if not url:
            continue
        if verified and verified != "yes":
            continue
        if online and online != "yes":
            continue

        candidates.append({
            "url": url,
            "label": 1,
            "label_name": "phishing",
            "source": "PhishTank",
            "source_id": (row.get("phish_id") or "").strip(),
            "source_metadata": (row.get("target") or "").strip(),
        })

    if len(candidates) < limit:
        raise RuntimeError(
            f"PhishTank returned only {len(candidates)} usable rows; "
            f"{limit} were requested."
        )

    rng = random.Random(seed)
    rng.shuffle(candidates)
    return candidates[:limit]


def fetch_legitimate_rows(limit: int, seed: int):
    raw_zip = _download(TRANCO_URL)

    with zipfile.ZipFile(io.BytesIO(raw_zip)) as archive:
        csv_names = [n for n in archive.namelist() if n.endswith(".csv")]
        if not csv_names:
            raise RuntimeError("Tranco archive did not contain a CSV file.")

        with archive.open(csv_names[0]) as f:
            text = io.TextIOWrapper(f, encoding="utf-8", errors="replace")
            reader = csv.reader(text)
            candidates = []
            for row in reader:
                if len(row) < 2:
                    continue
                rank, domain = row[0].strip(), row[1].strip().lower()
                if not domain or "." not in domain:
                    continue
                candidates.append({
                    "url": f"https://{domain}/",
                    "label": 0,
                    "label_name": "legitimate",
                    "source": "Tranco",
                    "source_id": rank,
                    "source_metadata": "top-ranked domain",
                })

    if len(candidates) < limit:
        raise RuntimeError(
            f"Tranco returned only {len(candidates)} usable rows; "
            f"{limit} were requested."
        )

    # Draw from a larger top-site pool so the sample is not just the first N.
    pool_size = min(len(candidates), max(limit * 20, 5000))
    pool = candidates[:pool_size]
    rng = random.Random(seed + 1)
    rng.shuffle(pool)
    return pool[:limit]


def write_dataset(rows, output: Path, seed: int):
    output.parent.mkdir(parents=True, exist_ok=True)

    rng = random.Random(seed + 2)
    rows = list(rows)
    rng.shuffle(rows)

    fieldnames = [
        "sample_id",
        "url",
        "label",
        "label_name",
        "source",
        "source_id",
        "source_metadata",
    ]

    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for i, row in enumerate(rows, start=1):
            writer.writerow({"sample_id": f"PG-{i:04d}", **row})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phishing", type=int, default=250)
    parser.add_argument("--legitimate", type=int, default=250)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    if args.phishing < 1 or args.legitimate < 1:
        raise SystemExit("Both class sizes must be at least 1.")

    print("Downloading verified phishing records from PhishTank...")
    phishing = fetch_phishing_rows(args.phishing, args.seed)

    print("Downloading legitimate domains from Tranco...")
    legitimate = fetch_legitimate_rows(args.legitimate, args.seed)

    write_dataset(phishing + legitimate, args.output, args.seed)

    total = args.phishing + args.legitimate
    print(f"Created {args.output}")
    print(f"Total samples: {total}")
    print(f"Phishing: {args.phishing}")
    print(f"Legitimate: {args.legitimate}")
    print("No listed URLs were visited; they were processed as text only.")


if __name__ == "__main__":
    main()
