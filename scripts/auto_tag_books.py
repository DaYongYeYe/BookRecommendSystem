from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import and_, func

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app import create_app, db
from app.models import Book, BookChapter, BookTag, Category, Tag
from app.services.work_catalog import WORK_CATEGORY_MAP


DEFAULT_MAX_TAGS = 5
MIN_TAG_SCORE = 4
MIN_BROAD_TAG_SCORE = 6
BROAD_TAG_CODES = {
    'daily_life',
    'essay',
    'family',
    'healing',
    'hot_blooded',
    'memory',
}
BROAD_WEAK_KEYWORDS = {
    'daily_life': {'生活'},
    'essay': {'人生', '观察'},
    'family': {'家族'},
    'healing': {'温暖', '轻松'},
    'hot_blooded': {'燃', '强者'},
    'memory': {'旧事', '往事'},
}

TAG_KEYWORDS: dict[str, tuple[str, ...]] = {
    'chosen_one': ('天命', '命运', '主角', '觉醒', '传承', '废柴', '少年', '圣子', '神子'),
    'leveling': ('升级', '等级', '练级', '修炼', '境界', '进阶', '突破', '变强', '打怪'),
    'sect': ('宗门', '门派', '师门', '掌门', '弟子', '长老', '仙门', '宗派'),
    'beast_taming': ('御兽', '灵兽', '妖兽', '宠兽', '驭兽', '召唤兽', '契约兽'),
    'treasure_hunt': ('寻宝', '宝藏', '秘境', '遗迹', '神器', '法宝', '古墓', '宝物'),
    'hot_blooded': ('热血', '燃', '大战', '战斗', '争霸', '爽文', '逆天', '强者'),
    'xianxia': ('仙侠', '修真', '修仙', '飞升', '金丹', '元婴', '灵根', '渡劫'),
    'sweet_love': ('甜宠', '甜文', '撒糖', '恋爱', '心动', '宠妻', '宠夫', '暗恋'),
    'marriage_first': ('先婚后爱', '契约婚姻', '闪婚', '联姻', '婚约', '新婚'),
    'redemption': ('救赎', '治愈彼此', '重逢', '破镜重圆', '救下', '被拯救'),
    'double_cleansing': ('双洁', '1v1', '一对一', '专情', '纯爱'),
    'career_woman': ('大女主', '女强', '事业', '女帝', '女将', '独立女性', '成长型女主'),
    'healing': ('治愈', '温暖', '疗愈', '陪伴', '慢热', '温情', '轻松'),
    'workplace': ('职场', '公司', '老板', '创业', '商业', '项目', '同事', '升职'),
    'counterattack': ('逆袭', '翻身', '打脸', '反击', '崛起', '复仇', '逆风'),
    'rich_family': ('豪门', '总裁', '财阀', '世家', '继承人', '商业联姻'),
    'daily_life': ('日常', '生活', '家常', '种田', '美食', '经营', '慢生活'),
    'system': ('系统', '面板', '任务', '奖励', '签到', '金手指', '绑定'),
    'comedy': ('轻喜剧', '搞笑', '欢乐', '爆笑', '沙雕', '吐槽', '喜剧'),
    'power_struggle': ('权谋', '夺嫡', '权臣', '谋略', '党争', '宫斗', '朝局'),
    'nation_building': ('建设', '基建', '种田', '治理', '发展', '城池', '领地'),
    'warfare': ('战争', '军队', '将军', '战场', '兵法', '征战', '军团'),
    'strategy': ('智斗', '布局', '谋局', '算计', '博弈', '推演', '破局'),
    'time_travel': ('穿越', '重生', '回到', '架空', '异世', '魂穿', '古代'),
    'court': ('朝堂', '皇帝', '王爷', '公主', '太子', '官场', '庙堂'),
    'inference': ('推理', '侦探', '线索', '谜案', '探案', '真相', '解谜'),
    'crime': ('刑侦', '罪案', '凶案', '警察', '法医', '犯罪', '嫌疑人'),
    'mind_game': ('心理', '博弈', '操控', '画像', '催眠', '心魔', '精神'),
    'reverse': ('反转', '逆转', '真相', '伏笔', '悬念', '身份揭晓'),
    'horror': ('惊悚', '恐怖', '灵异', '诡异', '怪谈', '鬼', '禁忌'),
    'survival': ('生存', '逃生', '求生', '末日', '危机', '荒野', '副本'),
    'mecha': ('机甲', '战甲', '机械', '驾驶舱', '装甲', '高达'),
    'starfield': ('星际', '宇宙', '星舰', '银河', '外星', '殖民星', '太空'),
    'apocalypse': ('末世', '废土', '丧尸', '灾变', '末日', '天灾', '避难所'),
    'ai': ('人工智能', 'ai', '机器人', '算法', '智能体', '仿生', '芯片'),
    'hard_scifi': ('硬科幻', '物理', '量子', '航天', '工程', '实验', '科学'),
    'time_space': ('时空', '时间', '空间', '虫洞', '平行世界', '时间线', '维度'),
    'family': ('家庭', '亲情', '父母', '兄妹', '家族', '故乡'),
    'memory': ('记忆', '回忆', '旧事', '往事', '失忆', '童年'),
    'essay': ('散文', '随笔', '文学', '人生', '纪实', '观察'),
    'focus': ('专注', '注意力', '效率', '自律', '习惯', '学习'),
    'relationship': ('关系', '沟通', '亲密关系', '社交', '边界感'),
    'emotion': ('情绪', '焦虑', '抑郁', '压力', '内耗', '心理成长'),
}

FIELD_WEIGHTS = {
    'title': 5,
    'latest_chapter': 4,
    'search_keywords': 4,
    'source_category': 2,
    'description': 2,
}


@dataclass(slots=True)
class BookTagContext:
    book_id: int
    title: str = ''
    description: str = ''
    source_category: str = ''
    latest_chapter: str = ''
    search_keywords: str = ''
    category_code: str = ''


@dataclass(slots=True)
class TagMatch:
    code: str
    score: int = 0
    reasons: set[str] = field(default_factory=set)


def normalize_text(value: str | None) -> str:
    return re.sub(r'\s+', ' ', (value or '').strip()).lower()


def parse_book_ids(raw: str | None) -> list[int]:
    result = []
    for item in (raw or '').split(','):
        item = item.strip()
        if item:
            result.append(int(item))
    return result


def latest_chapter_from_update_note(update_note: str | None) -> str:
    text = update_note or ''
    for pattern in (
        r'(?:最后章节|最新章节)\s*[:：]\s*([^；;]+)',
        r'(?:last chapter|latest chapter)\s*[:：]\s*([^；;]+)',
    ):
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            value = match.group(1).strip()
            if value and value != '未获取':
                return value
    return ''


def get_latest_chapter_titles(book_ids: list[int]) -> dict[int, str]:
    if not book_ids:
        return {}
    latest_no = (
        db.session.query(
            BookChapter.book_id.label('book_id'),
            func.max(BookChapter.chapter_no).label('chapter_no'),
        )
        .filter(BookChapter.book_id.in_(book_ids))
        .group_by(BookChapter.book_id)
        .subquery()
    )
    rows = (
        db.session.query(BookChapter.book_id, BookChapter.title)
        .join(
            latest_no,
            and_(
                BookChapter.book_id == latest_no.c.book_id,
                BookChapter.chapter_no == latest_no.c.chapter_no,
            ),
        )
        .all()
    )
    return {int(book_id): title or '' for book_id, title in rows}


def build_contexts(book_ids: list[int] | None = None, limit: int | None = None) -> list[BookTagContext]:
    query = (
        db.session.query(Book, Category)
        .outerjoin(Category, Category.id == Book.category_id)
        .filter(Book.is_deleted.is_(False))
        .order_by(Book.id.asc())
    )
    if book_ids:
        query = query.filter(Book.id.in_(book_ids))
    if limit:
        query = query.limit(limit)

    rows = query.all()
    row_book_ids = [int(book.id) for book, _category in rows]
    latest_title_map = get_latest_chapter_titles(row_book_ids)
    contexts = []
    for book, category in rows:
        category_parts = [
            category.code if category else '',
            category.name if category else '',
            category.en_name if category else '',
            book.subcategory_code or '',
        ]
        latest_chapter = latest_title_map.get(int(book.id)) or latest_chapter_from_update_note(book.update_note)
        contexts.append(
            BookTagContext(
                book_id=int(book.id),
                title=book.title or '',
                description=book.description or '',
                source_category=' '.join(item for item in category_parts if item),
                latest_chapter=latest_chapter or '',
                search_keywords=book.search_keywords or '',
                category_code=category.code if category else '',
            )
        )
    return contexts


def category_default_tag_codes(category_code: str | None) -> list[str]:
    if not category_code:
        return []
    return list(WORK_CATEGORY_MAP.get(category_code, {}).get('tag_codes', []))


def has_precise_evidence(match: TagMatch) -> bool:
    non_category_reasons = [reason for reason in match.reasons if reason != '分类默认']
    if not non_category_reasons:
        return False
    if match.code not in BROAD_TAG_CODES:
        return match.score >= MIN_TAG_SCORE

    weak_keywords = BROAD_WEAK_KEYWORDS.get(match.code, set())
    strong_reasons = []
    for reason in non_category_reasons:
        if reason.startswith(('标签名:', 'tag_code:')):
            strong_reasons.append(reason)
            continue
        field_name, _separator, keyword = reason.partition(':')
        if keyword and keyword in weak_keywords:
            continue
        if field_name in {'title', 'search_keywords', 'latest_chapter'}:
            strong_reasons.append(reason)
            continue
        if keyword:
            strong_reasons.append(reason)

    return match.score >= MIN_BROAD_TAG_SCORE and bool(strong_reasons)


def match_tags(context: BookTagContext, available_tags: dict[str, Tag], max_tags: int = DEFAULT_MAX_TAGS) -> list[TagMatch]:
    matches: dict[str, TagMatch] = {}

    def add(code: str, points: int, reason: str) -> None:
        if code not in available_tags:
            return
        item = matches.setdefault(code, TagMatch(code=code))
        item.score += points
        item.reasons.add(reason)

    for code in category_default_tag_codes(context.category_code):
        add(code, 1, '分类默认')

    fields = {
        'title': context.title,
        'description': context.description,
        'source_category': context.source_category,
        'latest_chapter': context.latest_chapter,
        'search_keywords': context.search_keywords,
    }
    normalized_fields = {name: normalize_text(value) for name, value in fields.items()}

    for code, keywords in TAG_KEYWORDS.items():
        for field_name, text in normalized_fields.items():
            if not text:
                continue
            for keyword in keywords:
                normalized_keyword = normalize_text(keyword)
                if normalized_keyword and normalized_keyword in text:
                    add(code, FIELD_WEIGHTS[field_name], f'{field_name}:{keyword}')
                    break

    combined_text = ' '.join(normalized_fields.values())
    for code, tag in available_tags.items():
        code_text = normalize_text(code.replace('_', ' '))
        compact_code_text = normalize_text(code.replace('_', ''))
        label_text = normalize_text(tag.label)
        if label_text and label_text in combined_text:
            add(code, 3, f'标签名:{tag.label}')
        if code_text and code_text in combined_text:
            add(code, 2, f'tag_code:{code}')
        elif compact_code_text and compact_code_text in combined_text:
            add(code, 2, f'tag_code:{code}')

    ranked = sorted(
        (match for match in matches.values() if has_precise_evidence(match)),
        key=lambda item: (-item.score, item.code),
    )
    return ranked[:max_tags]


def existing_book_tag_ids(book_ids: list[int]) -> dict[int, set[int]]:
    result = {book_id: set() for book_id in book_ids}
    if not book_ids:
        return result
    rows = (
        db.session.query(BookTag.book_id, BookTag.tag_id)
        .filter(BookTag.book_id.in_(book_ids))
        .all()
    )
    for book_id, tag_id in rows:
        result.setdefault(int(book_id), set()).add(int(tag_id))
    return result


def apply_auto_tags(
    *,
    book_ids: list[int] | None = None,
    limit: int | None = None,
    max_tags: int = DEFAULT_MAX_TAGS,
    replace: bool = False,
    dry_run: bool = False,
) -> dict[str, int]:
    available_tags = {tag.code: tag for tag in Tag.query.order_by(Tag.id.asc()).all()}
    contexts = build_contexts(book_ids=book_ids, limit=limit)
    target_book_ids = [context.book_id for context in contexts]
    existing_map = existing_book_tag_ids(target_book_ids)

    stats = {
        'books': len(contexts),
        'matched_books': 0,
        'created_relations': 0,
        'removed_relations': 0,
        'missing_matches': 0,
    }

    for context in contexts:
        matches = match_tags(context, available_tags, max_tags=max_tags)
        if not matches:
            stats['missing_matches'] += 1
            print(f'book={context.book_id} title={context.title} matched=none')
            continue

        stats['matched_books'] += 1
        tag_ids = [int(available_tags[match.code].id) for match in matches]
        current_ids = existing_map.get(context.book_id, set())
        print(
            f'book={context.book_id} title={context.title} matched='
            + ', '.join(f'{match.code}({match.score})' for match in matches)
        )

        if dry_run:
            continue

        if replace and current_ids:
            removed = BookTag.query.filter(BookTag.book_id == context.book_id).delete(synchronize_session=False)
            stats['removed_relations'] += int(removed or 0)
            current_ids = set()

        for tag_id in tag_ids:
            if tag_id in current_ids:
                continue
            db.session.add(BookTag(book_id=context.book_id, tag_id=tag_id))
            stats['created_relations'] += 1

    if dry_run:
        db.session.rollback()
    else:
        db.session.commit()
    return stats


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError('must be greater than 0')
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Automatically match catalog tags and write book_tags.')
    parser.add_argument('--book-ids', default='', help='Comma-separated local book IDs to tag. Defaults to all books.')
    parser.add_argument('--limit', type=positive_int, default=None, help='Maximum number of books to process.')
    parser.add_argument('--max-tags', type=positive_int, default=DEFAULT_MAX_TAGS, help='Maximum matched tags per book.')
    parser.add_argument('--replace', action='store_true', help='Remove existing book_tags for matched books before writing new tags.')
    parser.add_argument('--dry-run', action='store_true', help='Print matches without writing book_tags.')
    return parser


def main() -> int:
    args = build_parser().parse_args()
    app = create_app()
    with app.app_context():
        stats = apply_auto_tags(
            book_ids=parse_book_ids(args.book_ids),
            limit=args.limit,
            max_tags=args.max_tags,
            replace=args.replace,
            dry_run=args.dry_run,
        )
    print(
        'Auto tagging finished: '
        f"books={stats['books']} matched_books={stats['matched_books']} "
        f"created_relations={stats['created_relations']} removed_relations={stats['removed_relations']} "
        f"missing_matches={stats['missing_matches']} dry_run={args.dry_run}"
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
