"""
Quick CLI to inspect recent detections stored in SQLite, e.g. after
running `python main.py --once` a few times.

Usage:
    python report.py            # last 20 detections
    python report.py --limit 50
"""
import argparse
import json

from core.storage import recent_detections, init_db

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--limit", type=int, default=20)
    args = p.parse_args()

    init_db()
    rows = recent_detections(limit=args.limit)
    if not rows:
        print("No detections stored yet. Run `python main.py --once` first.")
        return

    for r in rows:
        apt = ", ".join(json.loads(r["apt_groups"])) or "Unattributed"
        techs = json.loads(r["techniques"])
        kc = json.loads(r["kill_chain_stages"])
        print("=" * 80)
        print(f"[{r['confidence']:.2f}] {r['title']}")
        print(f"  Source: {r['source']}  |  Published: {r['published']}")
        print(f"  URL: {r['url']}")
        print(f"  APT Groups: {apt}")
        print(f"  Techniques: {', '.join(t['id'] + ' ' + t['name'] for t in techs) or 'none'}")
        print(f"  Kill Chain: {' -> '.join(kc) or 'n/a'}")
        print(f"  Alerted: {'yes' if r['alerted'] else 'no'}")

if __name__ == "__main__":
    main()
