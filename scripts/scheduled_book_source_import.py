from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Keep scheduled importer logging separate from the dev server. On Windows,
# two processes rotating the same app.log can lock each other.
os.environ.setdefault('LOG_DIR', str(ROOT_DIR / 'instance' / 'logs' / 'book_source_importer'))

from app import create_app, db
from app.services.book_source_importer import DEFAULT_SOURCE_JSON_URL, import_book_source, import_existing_book_content


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError('must be greater than 0')
    return parsed


def non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError('must be greater than or equal to 0')
    return parsed


def request_delay(value: str) -> float:
    parsed = float(value)
    if parsed < 3:
        raise argparse.ArgumentTypeError('request delay must be at least 3 seconds')
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Run the authorized book source importer on a fixed schedule.',
    )
    parser.add_argument(
        '--source',
        default=os.environ.get('BOOK_SOURCE_URL') or DEFAULT_SOURCE_JSON_URL,
        help='Book source JSON/page URL, local JSON file, or comma-separated locations.',
    )
    parser.add_argument('--limit', type=positive_int, default=int(os.environ.get('BOOK_SOURCE_LIMIT', 1000)))
    parser.add_argument('--max-pages', type=positive_int, default=int(os.environ.get('BOOK_SOURCE_MAX_PAGES', 60)))
    parser.add_argument('--include-content', action='store_true', default=os.environ.get('BOOK_SOURCE_INCLUDE_CONTENT', '').lower() in {'1', 'true', 'yes', 'on'})
    parser.add_argument('--include-toc', action='store_true', default=os.environ.get('BOOK_SOURCE_INCLUDE_TOC', '').lower() in {'1', 'true', 'yes', 'on'})
    parser.add_argument('--overwrite-content', action='store_true', default=os.environ.get('BOOK_SOURCE_OVERWRITE_CONTENT', '').lower() in {'1', 'true', 'yes', 'on'})
    parser.add_argument('--random-sample', action='store_true', default=os.environ.get('BOOK_SOURCE_RANDOM_SAMPLE', '').lower() in {'1', 'true', 'yes', 'on'})
    parser.add_argument('--existing-only', action='store_true', default=os.environ.get('BOOK_SOURCE_EXISTING_ONLY', '').lower() in {'1', 'true', 'yes', 'on'})
    parser.add_argument(
        '--book-ids',
        default=os.environ.get('BOOK_SOURCE_BOOK_IDS', ''),
        help='Optional comma-separated local book IDs to backfill when --existing-only is used.',
    )
    parser.add_argument(
        '--max-chapters-per-book',
        type=non_negative_int,
        default=int(os.environ.get('BOOK_SOURCE_MAX_CHAPTERS_PER_BOOK', 0)),
        help='0 means all chapters when content import is enabled.',
    )
    parser.add_argument('--request-delay', type=request_delay, default=float(os.environ.get('BOOK_SOURCE_REQUEST_DELAY', 3)))
    parser.add_argument('--timeout', type=positive_int, default=int(os.environ.get('BOOK_SOURCE_TIMEOUT', 20)))
    parser.add_argument('--retries', type=non_negative_int, default=int(os.environ.get('BOOK_SOURCE_RETRIES', 2)))
    parser.add_argument(
        '--interval-minutes',
        type=positive_int,
        default=int(os.environ.get('BOOK_SOURCE_INTERVAL_MINUTES', 360)),
        help='How long to wait between import rounds when --loop is enabled.',
    )
    parser.add_argument(
        '--loop',
        action='store_true',
        help='Keep running on a fixed interval. Default is a single run per process.',
    )
    # Backward-compatible alias for older scripts; one-shot is now the default mode.
    parser.add_argument('--run-once', action='store_true', help=argparse.SUPPRESS)
    return parser


def log(message: str) -> None:
    print(f'[{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] {message}', flush=True)


def parse_book_ids(raw: str) -> list[int]:
    result = []
    for item in (raw or '').split(','):
        item = item.strip()
        if not item:
            continue
        result.append(int(item))
    return result


def run_round(args: argparse.Namespace) -> bool:
    app = create_app()
    with app.app_context():
        try:
            if args.existing_only:
                stats = import_existing_book_content(
                    source_location=args.source,
                    limit=args.limit,
                    book_ids=parse_book_ids(args.book_ids),
                    include_content=args.include_content,
                    max_chapters_per_book=args.max_chapters_per_book,
                    cookie=os.environ.get('BOOK_SOURCE_COOKIE'),
                    timeout=args.timeout,
                    retries=args.retries,
                    delay=args.request_delay,
                    overwrite_content=args.overwrite_content,
                )
            else:
                stats = import_book_source(
                    source_location=args.source,
                    limit=args.limit,
                    max_pages=args.max_pages,
                    include_toc=args.include_toc or args.include_content,
                    include_content=args.include_content,
                    max_chapters_per_book=args.max_chapters_per_book,
                    cookie=os.environ.get('BOOK_SOURCE_COOKIE'),
                    timeout=args.timeout,
                    retries=args.retries,
                    delay=args.request_delay,
                    dry_run=False,
                    overwrite_content=args.overwrite_content,
                    random_sample=args.random_sample,
                )
            log(
                'finished '
                f'candidates={stats.candidates} created={stats.created} updated={stats.updated} '
                f'failed={stats.failed} chapters={stats.chapters} paragraphs={stats.paragraphs} '
                f'failed_chapters={stats.failed_chapters} skipped_chapters={stats.skipped_chapters}'
            )
            if stats.errors:
                for item in stats.errors[:20]:
                    log(f'error {item}')
                if len(stats.errors) > 20:
                    log(f'error ... {len(stats.errors) - 20} more')
            return stats.failed == 0
        except Exception as exc:  # noqa: BLE001 - scheduler must keep future rounds alive.
            db.session.rollback()
            log(f'round failed: {exc}')
            return False


def main() -> int:
    args = build_parser().parse_args()
    if args.book_ids and not args.existing_only:
        log('book_ids is set but existing_only is disabled; book_ids will be ignored')

    one_shot = not args.loop or args.run_once
    log(
        'scheduler started '
        f'source={args.source} limit={args.limit} mode={"loop" if not one_shot else "run_once"} '
        f'interval_minutes={args.interval_minutes} '
        f'request_delay={args.request_delay}s include_content={args.include_content} '
        f'max_chapters_per_book={args.max_chapters_per_book} overwrite_content={args.overwrite_content} '
        f'random_sample={args.random_sample} existing_only={args.existing_only} book_ids={args.book_ids or "all"}'
    )
    while True:
        ok = run_round(args)
        if one_shot:
            return 0 if ok else 1
        sleep_seconds = args.interval_minutes * 60
        log(f'sleeping {args.interval_minutes} minutes before next round')
        time.sleep(sleep_seconds)


if __name__ == '__main__':
    raise SystemExit(main())
