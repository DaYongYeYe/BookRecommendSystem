from __future__ import annotations

import sys
from datetime import date, datetime, timedelta
from itertools import cycle
from pathlib import Path

from sqlalchemy import inspect, text
from werkzeug.security import generate_password_hash

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app import create_app, db
from app.services.tencent_cos import upload_text


PASSWORD_HASH = generate_password_hash("123456")
TENANT_ID = 1
BOOK_ID_START = 1001
BOOKS_PER_CATEGORY = 12
USER_ID_START = 101


def store_seed_content(content: str):
    result, error = upload_text(content, folder="book_chapters")
    if error or not result:
        raise RuntimeError(error or "failed to upload seed content")
    return result


CATEGORIES = [
    {
        "code": "fantasy",
        "name": "玄幻奇幻",
        "en_name": "Fantasy",
        "description": "东方玄幻、修真、异世冒险与成长爽文。",
        "cover": "https://picsum.photos/seed/category-fantasy/900/600",
        "is_highlighted": True,
    },
    {
        "code": "romance",
        "name": "言情小说",
        "en_name": "Romance",
        "description": "现代、古言、校园与治愈系情感故事。",
        "cover": "https://picsum.photos/seed/category-romance/900/600",
        "is_highlighted": True,
    },
    {
        "code": "urban",
        "name": "都市现实",
        "en_name": "Urban",
        "description": "职场、创业、家庭、城市生活与现实题材。",
        "cover": "https://picsum.photos/seed/category-urban/900/600",
        "is_highlighted": True,
    },
    {
        "code": "history",
        "name": "历史架空",
        "en_name": "History",
        "description": "权谋、朝堂、战争策略与时代群像。",
        "cover": "https://picsum.photos/seed/category-history/900/600",
        "is_highlighted": True,
    },
    {
        "code": "suspense",
        "name": "悬疑推理",
        "en_name": "Suspense",
        "description": "刑侦、心理博弈、密室、怪谈与反转谜题。",
        "cover": "https://picsum.photos/seed/category-suspense/900/600",
        "is_highlighted": True,
    },
    {
        "code": "scifi",
        "name": "科幻未来",
        "en_name": "Science Fiction",
        "description": "人工智能、星际文明、末日生存与硬科幻设定。",
        "cover": "https://picsum.photos/seed/category-scifi/900/600",
        "is_highlighted": True,
    },
    {
        "code": "literature",
        "name": "文学生活",
        "en_name": "Literature",
        "description": "现代文学、家庭记忆、地域叙事与细腻人生。",
        "cover": "https://picsum.photos/seed/category-literature/900/600",
        "is_highlighted": False,
    },
    {
        "code": "psychology",
        "name": "心理成长",
        "en_name": "Psychology",
        "description": "情绪管理、关系沟通、专注力与自我成长。",
        "cover": "https://picsum.photos/seed/category-psychology/900/600",
        "is_highlighted": False,
    },
]


TAGS = [
    ("chosen_one", "天命主角"),
    ("leveling", "升级流"),
    ("sect", "宗门"),
    ("beast_taming", "御兽"),
    ("treasure_hunt", "寻宝"),
    ("hot_blooded", "热血"),
    ("xianxia", "仙侠"),
    ("sweet_love", "甜宠"),
    ("marriage_first", "先婚后爱"),
    ("redemption", "救赎"),
    ("double_cleansing", "双向奔赴"),
    ("career_woman", "大女主"),
    ("healing", "治愈"),
    ("workplace", "职场"),
    ("counterattack", "逆袭"),
    ("rich_family", "豪门"),
    ("daily_life", "日常生活"),
    ("system", "系统流"),
    ("comedy", "轻喜剧"),
    ("power_struggle", "权谋"),
    ("nation_building", "基建"),
    ("warfare", "战争"),
    ("strategy", "智斗"),
    ("time_travel", "穿越"),
    ("court", "朝堂"),
    ("inference", "推理"),
    ("crime", "刑侦"),
    ("mind_game", "心理博弈"),
    ("reverse", "反转"),
    ("horror", "惊悚"),
    ("survival", "生存"),
    ("mecha", "机甲"),
    ("starfield", "星际"),
    ("apocalypse", "末世"),
    ("ai", "人工智能"),
    ("hard_scifi", "硬科幻"),
    ("time_space", "时空"),
    ("family", "家庭"),
    ("memory", "记忆"),
    ("essay", "散文感"),
    ("focus", "专注"),
    ("relationship", "亲密关系"),
    ("emotion", "情绪管理"),
]


BLUEPRINTS = {
    "fantasy": {
        "subcategories": ["eastern_fantasy", "western_fantasy", "xianxia"],
        "tags": ["chosen_one", "leveling", "sect", "beast_taming", "treasure_hunt", "hot_blooded", "xianxia"],
        "titles": ["云荒剑籍", "九州灵契", "青崖问仙", "星河御兽录", "长夜铸魂师", "万象山海图", "烬土神庭", "玄门旧灯", "龙骨渡海", "天墟行者", "灵潮纪事", "不朽炉心"],
        "authors": ["墨白川", "青岚子", "扶光", "折枝", "迟野", "南宫野", "寒星渡", "云栖"],
        "tone": "以少年成长、宗门试炼和古老遗迹为主线，节奏明快，设定层层展开。",
    },
    "romance": {
        "subcategories": ["modern_romance", "ancient_romance", "campus_romance"],
        "tags": ["sweet_love", "marriage_first", "redemption", "double_cleansing", "career_woman", "healing"],
        "titles": ["春日慢信", "月光停在第七街", "她与海风同来", "槐花落在旧庭院", "迟来的告白练习", "雾城心动法则", "玻璃温室", "南巷来信", "雪夜便利店", "星星不说谎", "你比雨季清晰", "杏仁糖与告别"],
        "authors": ["林见鹿", "舒晚", "岑枝", "小满", "温以宁", "白桃未熟", "季雨眠", "许知遥"],
        "tone": "关注亲密关系中的陪伴、选择与和解，甜度适中，情绪落点温柔。",
    },
    "urban": {
        "subcategories": ["modern_city", "workplace", "supernatural_city"],
        "tags": ["workplace", "counterattack", "rich_family", "daily_life", "system", "comedy"],
        "titles": ["凌晨三点的项目组", "逆风合伙人", "城市边缘日志", "我的便利店会算命", "旧楼里的创业课", "江湾金融街", "系统让我准时下班", "中年重启计划", "人间烟火算法", "地铁十号线奇遇", "小城大厂", "周一不加班"],
        "authors": ["陈屿", "周不晚", "顾行舟", "北桥", "唐半夏", "陆知行", "赵晴川", "江以南"],
        "tone": "把职场压力、城市关系和普通人的自我修复写得轻快真实。",
    },
    "history": {
        "subcategories": ["overhead_history", "war_strategy", "officialdom"],
        "tags": ["power_struggle", "nation_building", "warfare", "strategy", "time_travel", "court"],
        "titles": ["长安策", "归燕台", "山河入局", "青史无名客", "北境粮道", "明堂夜雨", "旧朝新相", "大梁巡盐记", "烽火账簿", "一品女官", "江山如棋", "云台十二策"],
        "authors": ["谢无衣", "宋砚", "陆青珩", "沈令仪", "贺兰舟", "闻人策", "白鹿鸣", "顾昭"],
        "tone": "以朝堂权谋、民生财政和战事布局推动剧情，群像感较强。",
    },
    "suspense": {
        "subcategories": ["mystery", "crime", "horror"],
        "tags": ["inference", "crime", "mind_game", "reverse", "horror", "survival"],
        "titles": ["第十七个目击者", "雨巷无声", "消失的蓝色档案", "旧钟楼密谈", "晚班列车", "心理侧写师手记", "零点来电", "空房间里的脚印", "镜中嫌疑人", "灰线追踪", "暗门之后", "雪地证词"],
        "authors": ["秦越", "叶岑", "罗十七", "宁川", "段小楼", "许观澜", "闻舟", "梁北辰"],
        "tone": "案件推进扎实，线索公平，适合喜欢推理、反转与心理博弈的读者。",
    },
    "scifi": {
        "subcategories": ["future_world", "interstellar", "post_apocalypse"],
        "tags": ["mecha", "starfield", "apocalypse", "ai", "hard_scifi", "time_space"],
        "titles": ["深空回声", "第九次日出", "仿生人不会做梦", "星门以西", "废土天气预报", "月球旧仓库", "时间折叠师", "银河边境站", "低温城市", "火星邮差", "最后的蓝鲸信号", "机械海"],
        "authors": ["星野川", "韩序", "纪原", "白令", "程舟", "艾以默", "苏沉", "顾量子"],
        "tone": "融合硬科幻设定与人的选择，强调文明尺度下的孤独、责任和希望。",
    },
    "literature": {
        "subcategories": ["modern_life", "family_memory", "regional_story"],
        "tags": ["family", "memory", "healing", "daily_life", "essay"],
        "titles": ["灯塔以南", "旧照相馆", "河岸早餐铺", "漫长的夏末", "小镇邮局", "雨停之后", "纸上故乡", "邻人之书", "晚风穿过巷口", "母亲的蓝围裙", "浮桥日记", "白墙上的影子"],
        "authors": ["罗欢", "蓝小溪", "方禾", "乔木", "许栀", "阿衡", "黎澈", "苏南星"],
        "tone": "写家庭记忆、地方生活和缓慢变化中的普通人，文风克制细腻。",
    },
    "psychology": {
        "subcategories": ["self_growth", "relationship", "focus_method"],
        "tags": ["focus", "relationship", "emotion", "healing", "daily_life"],
        "titles": ["把注意力还给自己", "情绪整理手册", "慢慢变清晰", "亲密关系的边界", "不内耗练习", "高敏感自救指南", "专注力复位", "疲惫时代的休息课", "沟通不是赢", "自洽的答案", "和焦虑坐一会儿", "人生小步重启"],
        "authors": ["周若安", "林以棠", "许清河", "沈嘉木", "梁书宁", "温北辰", "唐一禾", "孟知微"],
        "tone": "用具体场景讲自我照顾、关系沟通和行动恢复，适合通勤或睡前阅读。",
    },
}


READER_NAMES = [
    ("mock_reader_01", "林安安", "北京", "海淀"),
    ("mock_reader_02", "陈一舟", "上海", "浦东"),
    ("mock_reader_03", "周小满", "广东", "广州"),
    ("mock_reader_04", "许青禾", "浙江", "杭州"),
    ("mock_reader_05", "顾南星", "江苏", "南京"),
    ("mock_reader_06", "白鹿鸣", "四川", "成都"),
    ("mock_reader_07", "唐知夏", "湖北", "武汉"),
    ("mock_reader_08", "宋遥", "福建", "厦门"),
    ("mock_reader_09", "陆景明", "山东", "青岛"),
    ("mock_reader_10", "温书予", "陕西", "西安"),
    ("mock_reader_11", "叶初晴", "重庆", "渝中"),
    ("mock_reader_12", "秦川", "河南", "郑州"),
    ("mock_creator_01", "墨白川", "湖南", "长沙"),
    ("mock_creator_02", "林见鹿", "云南", "昆明"),
    ("mock_creator_03", "星野川", "天津", "和平"),
    ("mock_creator_04", "谢无衣", "广西", "桂林"),
]


def execute(sql: str, params: dict | None = None):
    db.session.execute(text(sql), params or {})


def has_table(inspector, table_name: str) -> bool:
    return table_name in set(inspector.get_table_names())


def column_names(inspector, table_name: str) -> set[str]:
    if not has_table(inspector, table_name):
        return set()
    return {col["name"] for col in inspector.get_columns(table_name)}


def ensure_column(inspector, table_name: str, column_name: str, ddl: str):
    if table_name in inspector.get_table_names() and column_name not in column_names(inspector, table_name):
        execute(f"ALTER TABLE {table_name} ADD COLUMN {ddl}")
        db.session.commit()


def ensure_chapter_compatibility():
    inspector = inspect(db.engine)
    if not has_table(inspector, "book_chapters"):
        return
    ensure_column(inspector, "book_chapters", "chapter_key", "chapter_key VARCHAR(64) NULL")
    inspector = inspect(db.engine)
    ensure_column(inspector, "book_chapters", "chapter_no", "chapter_no INT NOT NULL DEFAULT 1")
    inspector = inspect(db.engine)
    ensure_column(inspector, "book_chapters", "created_at", "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP")
    inspector = inspect(db.engine)
    ensure_column(
        inspector,
        "book_chapters",
        "updated_at",
        "updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP",
    )
    cols = column_names(inspector, "book_chapters")
    if {"chapter_key", "order_no"}.issubset(cols):
        execute(
            """
            UPDATE book_chapters
            SET chapter_key = CONCAT('chapter-', COALESCE(order_no, id))
            WHERE chapter_key IS NULL OR chapter_key = ''
            """
        )
    if {"chapter_no", "order_no"}.issubset(cols):
        execute("UPDATE book_chapters SET chapter_no = COALESCE(order_no, chapter_no, 1)")
    db.session.commit()


def upsert_categories_and_tags():
    for item in CATEGORIES:
        execute(
            """
            INSERT INTO categories (code, name, en_name, description, cover, is_highlighted)
            VALUES (:code, :name, :en_name, :description, :cover, :is_highlighted)
            ON DUPLICATE KEY UPDATE
              name = VALUES(name),
              en_name = VALUES(en_name),
              description = VALUES(description),
              cover = VALUES(cover),
              is_highlighted = VALUES(is_highlighted)
            """,
            item,
        )

    for code, label in TAGS:
        execute(
            """
            INSERT INTO tags (code, label)
            VALUES (:code, :label)
            ON DUPLICATE KEY UPDATE label = VALUES(label)
            """,
            {"code": code, "label": label},
        )


def upsert_users():
    now = datetime.now()
    for offset, (username, name, province, city) in enumerate(READER_NAMES):
        user_id = USER_ID_START + offset
        is_creator = username.startswith("mock_creator")
        execute(
            """
            INSERT INTO users (
              id, username, name, pen_name, email, avatar_url, age, province, city,
              password_hash, role, is_super_admin, tenant_id, created_at, updated_at
            )
            VALUES (
              :id, :username, :name, :pen_name, :email, :avatar_url, :age, :province, :city,
              :password_hash, :role, 0, :tenant_id, :created_at, :updated_at
            )
            ON DUPLICATE KEY UPDATE
              name = VALUES(name),
              pen_name = VALUES(pen_name),
              avatar_url = VALUES(avatar_url),
              age = VALUES(age),
              province = VALUES(province),
              city = VALUES(city),
              password_hash = VALUES(password_hash),
              role = VALUES(role),
              tenant_id = VALUES(tenant_id),
              updated_at = VALUES(updated_at)
            """,
            {
                "id": user_id,
                "username": username,
                "name": name,
                "pen_name": name if is_creator else None,
                "email": f"{username}@book.local",
                "avatar_url": f"https://api.dicebear.com/7.x/initials/svg?seed={username}",
                "age": 20 + (offset * 3) % 24,
                "province": province,
                "city": city,
                "password_hash": PASSWORD_HASH,
                "role": "creator" if is_creator else "user",
                "tenant_id": TENANT_ID,
                "created_at": now - timedelta(days=offset * 9 + 3),
                "updated_at": now,
            },
        )


def fetch_id_map(table_name: str, code_column: str = "code") -> dict[str, int]:
    rows = db.session.execute(text(f"SELECT id, {code_column} FROM {table_name}")).all()
    return {row[1]: int(row[0]) for row in rows}


def build_books(category_ids: dict[str, int]):
    today = date.today()
    books = []
    book_id = BOOK_ID_START
    creator_cycle = cycle(range(USER_ID_START + 12, USER_ID_START + 16))
    for category_index, category in enumerate(CATEGORIES):
        blueprint = BLUEPRINTS[category["code"]]
        for idx, title in enumerate(blueprint["titles"], start=1):
            category_code = category["code"]
            rating = round(7.9 + ((idx * 7 + category_index * 3) % 17) / 10, 1)
            if rating > 9.6:
                rating = 9.6
            rating_count = 420 + (idx * 317) + category_index * 710
            recent_reads = 6200 + idx * 4700 + category_index * 13500 + (idx % 4) * 8300
            published_at = datetime.combine(today - timedelta(days=(idx * 5 + category_index * 11) % 210), datetime.min.time())
            completion_status = "completed" if idx in {2, 5, 8, 11} else "ongoing"
            word_count = 86000 + idx * 36000 + category_index * 18000
            subtitle_pool = [
                "本周热读，口碑稳定上升",
                "适合睡前和通勤慢慢读",
                "高收藏读者正在追更",
                "新读者友好的入坑选择",
            ]
            books.append(
                {
                    "id": book_id,
                    "title": title,
                    "subtitle": subtitle_pool[(idx + category_index) % len(subtitle_pool)],
                    "author": blueprint["authors"][(idx + category_index) % len(blueprint["authors"])],
                    "description": f"《{title}》是一部{category['name']}方向的模拟作品，{blueprint['tone']}人物关系、冲突节奏和章节钩子都按线上阅读口味设计，适合作为推荐、搜索、榜单和详情页展示数据。",
                    "cover": f"https://picsum.photos/seed/book-rich-{book_id}/480/640",
                    "subcategory_code": blueprint["subcategories"][(idx - 1) % len(blueprint["subcategories"])],
                    "score": rating,
                    "rating": rating,
                    "rating_count": rating_count,
                    "recent_reads": recent_reads,
                    "home_recommendation_reason": f"{category['name']}读者近期收藏较多，标签集中在{'、'.join(blueprint['tags'][:3])}。",
                    "search_keywords": f"{title} {category['name']} {category['en_name']} {' '.join(blueprint['tags'])}",
                    "is_featured": 1 if idx in {1, 4, 9} else 0,
                    "category_id": category_ids[category_code],
                    "word_count": word_count,
                    "completion_status": completion_status,
                    "suitable_audience": f"适合喜欢{category['name']}、节奏清晰、情绪反馈明确的读者。",
                    "price_type": "vip" if idx in {3, 7, 12} else "free",
                    "creation_type": "original",
                    "protagonist": "主角在关键选择中逐步建立自己的秩序和关系网络。",
                    "worldview": f"{category['name']}背景下的多线叙事，兼顾日常细节与主线推进。",
                    "author_message": "感谢收藏与追读，模拟数据用于本地演示。",
                    "author_notice": "每日 20:00 左右更新，特殊情况会在作品公告说明。",
                    "copyright_notice": "本作品为本地演示模拟数据，非真实出版物。",
                    "update_note": "最近章节推进了主线冲突，并留下新的悬念。",
                    "audit_status": "approved",
                    "shelf_status": "up",
                    "status": "published",
                    "creator_id": next(creator_cycle),
                    "tenant_id": TENANT_ID,
                    "published_at": published_at,
                    "created_at": published_at - timedelta(days=7),
                    "updated_at": datetime.now(),
                    "is_deleted": 0,
                }
            )
            book_id += 1
    return books


def upsert_books(books: list[dict]):
    sql = """
        INSERT INTO books (
          id, title, subtitle, author, description, cover, subcategory_code, score, rating,
          rating_count, recent_reads, home_recommendation_reason, search_keywords, is_featured,
          category_id, word_count, completion_status, suitable_audience, price_type, creation_type,
          protagonist, worldview, author_message, author_notice, copyright_notice, update_note,
          audit_status, shelf_status, status, creator_id, tenant_id, published_at, created_at,
          updated_at, is_deleted
        )
        VALUES (
          :id, :title, :subtitle, :author, :description, :cover, :subcategory_code, :score, :rating,
          :rating_count, :recent_reads, :home_recommendation_reason, :search_keywords, :is_featured,
          :category_id, :word_count, :completion_status, :suitable_audience, :price_type, :creation_type,
          :protagonist, :worldview, :author_message, :author_notice, :copyright_notice, :update_note,
          :audit_status, :shelf_status, :status, :creator_id, :tenant_id, :published_at, :created_at,
          :updated_at, :is_deleted
        )
        ON DUPLICATE KEY UPDATE
          title = VALUES(title),
          subtitle = VALUES(subtitle),
          author = VALUES(author),
          description = VALUES(description),
          cover = VALUES(cover),
          subcategory_code = VALUES(subcategory_code),
          score = VALUES(score),
          rating = VALUES(rating),
          rating_count = VALUES(rating_count),
          recent_reads = VALUES(recent_reads),
          home_recommendation_reason = VALUES(home_recommendation_reason),
          search_keywords = VALUES(search_keywords),
          is_featured = VALUES(is_featured),
          category_id = VALUES(category_id),
          word_count = VALUES(word_count),
          completion_status = VALUES(completion_status),
          suitable_audience = VALUES(suitable_audience),
          price_type = VALUES(price_type),
          creation_type = VALUES(creation_type),
          protagonist = VALUES(protagonist),
          worldview = VALUES(worldview),
          author_message = VALUES(author_message),
          author_notice = VALUES(author_notice),
          copyright_notice = VALUES(copyright_notice),
          update_note = VALUES(update_note),
          audit_status = VALUES(audit_status),
          shelf_status = VALUES(shelf_status),
          status = VALUES(status),
          creator_id = VALUES(creator_id),
          tenant_id = VALUES(tenant_id),
          published_at = VALUES(published_at),
          updated_at = VALUES(updated_at),
          is_deleted = VALUES(is_deleted)
    """
    for book in books:
        execute(sql, book)


def upsert_book_tags(books: list[dict], tag_ids: dict[str, int]):
    for book in books:
        category_code = next(item["code"] for item in CATEGORIES if item["name"] in book["description"])
        tag_codes = BLUEPRINTS[category_code]["tags"]
        chosen = [tag_codes[(book["id"] + i) % len(tag_codes)] for i in range(3)]
        for code in chosen:
            execute(
                """
                INSERT INTO book_tags (book_id, tag_id)
                VALUES (:book_id, :tag_id)
                ON DUPLICATE KEY UPDATE tag_id = VALUES(tag_id)
                """,
                {"book_id": book["id"], "tag_id": tag_ids[code]},
            )


def upsert_reader_content(books: list[dict]):
    sample_books = books[:16]
    now = datetime.now()
    for book in sample_books:
        for chapter_no in range(1, 4):
            chapter_id = book["id"] * 100 + chapter_no
            revision_id = chapter_id * 10 + 1
            section_key = f"rich-{book['id']}-chapter-{chapter_no}"
            chapter_title = ["开篇：新的线索", "中段：关系转折", "尾声：下一次选择"][chapter_no - 1]
            paragraphs = [
                f"《{book['title']}》第 {chapter_no} 章从一个很日常的场景切入，让人物在细节里自然露出目标和软肋。",
                f"这一节的冲突没有急着给答案，而是把选择摆到读者面前：继续相信、暂时退后，或重新建立规则。",
                f"章节结尾留下一个轻巧的钩子，既推动主线，也让读者愿意点开下一章继续读下去。",
            ]
            content_text = "\n\n".join(paragraphs)
            stored_content = store_seed_content(content_text)
            execute(
                """
                INSERT INTO book_chapters (
                  id, book_id, chapter_key, chapter_no, title, status,
                  published_revision_id, tenant_id, created_by, created_at, updated_at
                )
                VALUES (
                  :id, :book_id, :chapter_key, :chapter_no, :title, 'published',
                  :published_revision_id, :tenant_id, :created_by, :created_at, :updated_at
                )
                ON DUPLICATE KEY UPDATE
                  chapter_key = VALUES(chapter_key),
                  chapter_no = VALUES(chapter_no),
                  title = VALUES(title),
                  status = VALUES(status),
                  published_revision_id = VALUES(published_revision_id),
                  tenant_id = VALUES(tenant_id),
                  created_by = VALUES(created_by),
                  updated_at = VALUES(updated_at)
                """,
                {
                    "id": chapter_id,
                    "book_id": book["id"],
                    "chapter_key": section_key,
                    "chapter_no": chapter_no,
                    "title": chapter_title,
                    "published_revision_id": revision_id,
                    "tenant_id": TENANT_ID,
                    "created_by": book["creator_id"],
                    "created_at": now - timedelta(days=chapter_no + 3),
                    "updated_at": now,
                },
            )
            execute(
                """
                INSERT INTO book_chapter_revisions (
                  id, chapter_id, version_no, title, content_text, content_url, content_md5, summary, status,
                  submitted_at, reviewed_at, reviewed_by, published_at, created_by, tenant_id,
                  created_at, updated_at
                )
                VALUES (
                  :id, :chapter_id, 1, :title, NULL, :content_url, :content_md5, :summary, 'published',
                  :submitted_at, :reviewed_at, 1, :published_at, :created_by, :tenant_id,
                  :created_at, :updated_at
                )
                ON DUPLICATE KEY UPDATE
                  title = VALUES(title),
                  content_text = NULL,
                  content_url = VALUES(content_url),
                  content_md5 = VALUES(content_md5),
                  summary = VALUES(summary),
                  status = VALUES(status),
                  reviewed_at = VALUES(reviewed_at),
                  published_at = VALUES(published_at),
                  created_by = VALUES(created_by),
                  tenant_id = VALUES(tenant_id),
                  updated_at = VALUES(updated_at)
                """,
                {
                    "id": revision_id,
                    "chapter_id": chapter_id,
                    "title": chapter_title,
                    "content_url": stored_content["url"],
                    "content_md5": stored_content["md5"],
                    "summary": f"{book['title']}的第 {chapter_no} 个阅读片段，适合测试在线阅读器。",
                    "submitted_at": now - timedelta(days=chapter_no + 2),
                    "reviewed_at": now - timedelta(days=chapter_no + 1),
                    "published_at": now - timedelta(days=chapter_no),
                    "created_by": book["creator_id"],
                    "tenant_id": TENANT_ID,
                    "created_at": now - timedelta(days=chapter_no + 3),
                    "updated_at": now,
                },
            )
            execute(
                """
                INSERT INTO reader_sections (book_id, section_key, title, summary, level, order_no, created_at)
                VALUES (:book_id, :section_key, :title, :summary, 1, :order_no, :created_at)
                ON DUPLICATE KEY UPDATE
                  title = VALUES(title),
                  summary = VALUES(summary),
                  level = VALUES(level),
                  order_no = VALUES(order_no)
                """,
                {
                    "book_id": book["id"],
                    "section_key": section_key,
                    "title": chapter_title,
                    "summary": f"{book['title']}章节摘要，用于阅读器目录展示。",
                    "order_no": chapter_no,
                    "created_at": now,
                },
            )
            section_id = db.session.execute(
                text("SELECT id FROM reader_sections WHERE book_id=:book_id AND section_key=:section_key"),
                {"book_id": book["id"], "section_key": section_key},
            ).scalar_one()
            execute("DELETE FROM reader_paragraphs WHERE section_id = :section_id", {"section_id": section_id})


def upsert_interactions(books: list[dict]):
    seeded_user_ids = list(range(USER_ID_START, USER_ID_START + len(READER_NAMES)))
    reader_user_ids = seeded_user_ids[:12]
    book_ids = [book["id"] for book in books]

    execute("DELETE FROM book_analytics_events WHERE session_id LIKE 'rich-seed-%'")
    execute(
        "DELETE FROM recommendation_feedback WHERE user_id BETWEEN :start AND :end AND book_id BETWEEN :book_start AND :book_end",
        {"start": USER_ID_START, "end": USER_ID_START + len(READER_NAMES), "book_start": BOOK_ID_START, "book_end": BOOK_ID_START + len(books) + 10},
    )

    now = datetime.now()
    for user_index, user_id in enumerate(reader_user_ids):
        for pick in range(10):
            book_id = book_ids[(user_index * 7 + pick * 5) % len(book_ids)]
            execute(
                """
                INSERT INTO user_shelf (user_id, book_id, created_at)
                VALUES (:user_id, :book_id, :created_at)
                ON DUPLICATE KEY UPDATE created_at = VALUES(created_at)
                """,
                {"user_id": user_id, "book_id": book_id, "created_at": now - timedelta(days=pick * 2 + user_index)},
            )
        for pick in range(6):
            book_id = book_ids[(user_index * 11 + pick * 3) % len(book_ids)]
            execute(
                """
                INSERT INTO user_reading_progress (
                  user_id, book_id, section_id, paragraph_id, scroll_percent, created_at, updated_at
                )
                VALUES (:user_id, :book_id, :section_id, :paragraph_id, :scroll_percent, :created_at, :updated_at)
                ON DUPLICATE KEY UPDATE
                  section_id = VALUES(section_id),
                  paragraph_id = VALUES(paragraph_id),
                  scroll_percent = VALUES(scroll_percent),
                  updated_at = VALUES(updated_at)
                """,
                {
                    "user_id": user_id,
                    "book_id": book_id,
                    "section_id": f"rich-{book_id}-chapter-{(pick % 3) + 1}",
                    "paragraph_id": f"rich-{book_id}-chapter-{(pick % 3) + 1}-p{(pick % 3) + 1}",
                    "scroll_percent": round(18 + ((user_index + pick) * 9) % 78, 2),
                    "created_at": now - timedelta(days=pick + 8),
                    "updated_at": now - timedelta(hours=pick * 5 + user_index),
                },
            )
        for pick in range(8):
            book_id = book_ids[(user_index * 13 + pick * 2) % len(book_ids)]
            execute(
                """
                INSERT INTO recommendation_feedback (user_id, book_id, action, created_at)
                VALUES (:user_id, :book_id, :action, :created_at)
                """,
                {
                    "user_id": user_id,
                    "book_id": book_id,
                    "action": ["click", "like", "add_shelf", "dismiss"][pick % 4],
                    "created_at": now - timedelta(days=pick % 6, hours=user_index),
                },
            )

    event_types = ["view", "read", "click", "finish_chapter"]
    geo_labels = ["北京", "上海", "广州", "杭州", "成都", "武汉", "南京", "西安"]
    age_groups = ["18-24", "25-30", "31-40", "40+"]
    for index, book in enumerate(books):
        for event_no in range(5):
            execute(
                """
                INSERT INTO book_analytics_events (
                  book_id, user_id, event_type, session_id, read_duration_seconds,
                  geo_label, age_group, created_at
                )
                VALUES (
                  :book_id, :user_id, :event_type, :session_id, :read_duration_seconds,
                  :geo_label, :age_group, :created_at
                )
                """,
                {
                    "book_id": book["id"],
                    "user_id": reader_user_ids[(index + event_no) % len(reader_user_ids)],
                    "event_type": event_types[(index + event_no) % len(event_types)],
                    "session_id": f"rich-seed-{book['id']}-{event_no}",
                    "read_duration_seconds": 120 + ((index + 1) * (event_no + 3) * 37) % 1800,
                    "geo_label": geo_labels[(index + event_no) % len(geo_labels)],
                    "age_group": age_groups[(index + event_no) % len(age_groups)],
                    "created_at": now - timedelta(days=(index + event_no) % 14, hours=event_no * 2),
                },
            )


def upsert_social_content(books: list[dict]):
    now = datetime.now()
    reader_ids = list(range(USER_ID_START, USER_ID_START + 12))
    comments = [
        "节奏很稳，适合加入书架慢慢追。",
        "人物关系比较自然，读起来没有负担。",
        "开头钩子不错，后面展开也有期待感。",
        "标签和简介挺准，确实是我会点开的类型。",
    ]
    review_templates = [
        "这本的优点是节奏清楚，设定不堆砌，适合想快速进入状态的读者。",
        "人物动机写得比较明确，读到中段会开始关心后续选择。",
        "作为本地演示数据很够用，封面、评分、评论和阅读热度都比较完整。",
    ]
    for idx, book in enumerate(books[:36]):
        for c_idx in range(2):
            comment_id = 200000 + idx * 10 + c_idx
            execute(
                """
                INSERT INTO reader_book_comments (id, book_id, author, content, tenant_id, created_at)
                VALUES (:id, :book_id, :author, :content, :tenant_id, :created_at)
                ON DUPLICATE KEY UPDATE
                  author = VALUES(author),
                  content = VALUES(content),
                  tenant_id = VALUES(tenant_id),
                  created_at = VALUES(created_at)
                """,
                {
                    "id": comment_id,
                    "book_id": book["id"],
                    "author": READER_NAMES[(idx + c_idx) % 12][1],
                    "content": comments[(idx + c_idx) % len(comments)],
                    "tenant_id": TENANT_ID,
                    "created_at": now - timedelta(days=(idx + c_idx) % 20),
                },
            )
        review_id = 300000 + idx
        execute(
            """
            INSERT INTO reviews (id, user_id, book_id, content, likes_count, comments_count, created_at)
            VALUES (:id, :user_id, :book_id, :content, :likes_count, :comments_count, :created_at)
            ON DUPLICATE KEY UPDATE
              user_id = VALUES(user_id),
              book_id = VALUES(book_id),
              content = VALUES(content),
              likes_count = VALUES(likes_count),
              comments_count = VALUES(comments_count),
              created_at = VALUES(created_at)
            """,
            {
                "id": review_id,
                "user_id": reader_ids[idx % len(reader_ids)],
                "book_id": book["id"],
                "content": review_templates[idx % len(review_templates)],
                "likes_count": 6 + (idx * 3) % 58,
                "comments_count": 1 + idx % 4,
                "created_at": now - timedelta(days=idx % 18),
            },
        )
        for like_offset in range(3):
            execute(
                """
                INSERT INTO review_likes (review_id, user_id, is_like, created_at)
                VALUES (:review_id, :user_id, 1, :created_at)
                ON DUPLICATE KEY UPDATE is_like = VALUES(is_like), created_at = VALUES(created_at)
                """,
                {
                    "review_id": review_id,
                    "user_id": reader_ids[(idx + like_offset + 2) % len(reader_ids)],
                    "created_at": now - timedelta(days=like_offset),
                },
            )


def upsert_optional_moods(books: list[dict]):
    inspector = inspect(db.engine)
    if not has_table(inspector, "moods") or not has_table(inspector, "mood_book_recommendations"):
        return
    moods = [
        ("healing", "想被治愈", "hugeicons:cloud-01"),
        ("focus", "想要专注", "hugeicons:target-02"),
        ("adventure", "想看冒险", "hugeicons:route-02"),
        ("brainstorm", "想开脑洞", "hugeicons:flash"),
    ]
    for mood_id, label, icon in moods:
        execute(
            """
            INSERT INTO moods (id, label, icon)
            VALUES (:id, :label, :icon)
            ON DUPLICATE KEY UPDATE label = VALUES(label), icon = VALUES(icon)
            """,
            {"id": mood_id, "label": label, "icon": icon},
        )
    mood_map = {
        "healing": ["romance", "literature", "psychology"],
        "focus": ["psychology", "history", "scifi"],
        "adventure": ["fantasy", "history", "scifi"],
        "brainstorm": ["scifi", "suspense", "fantasy"],
    }
    for mood_id, category_codes in mood_map.items():
        weight = 100
        for book in [item for item in books if any(code in item["search_keywords"] for code in category_codes)][:16]:
            execute(
                """
                INSERT INTO mood_book_recommendations (mood_id, book_id, weight)
                VALUES (:mood_id, :book_id, :weight)
                ON DUPLICATE KEY UPDATE weight = VALUES(weight)
                """,
                {"mood_id": mood_id, "book_id": book["id"], "weight": weight},
            )
            weight -= 3


def print_counts():
    tables = [
        "users",
        "categories",
        "tags",
        "books",
        "book_tags",
        "book_chapters",
        "book_chapter_revisions",
        "reader_sections",
        "reader_paragraphs",
        "user_shelf",
        "user_reading_progress",
        "book_analytics_events",
        "reader_book_comments",
        "reviews",
    ]
    print("\nSeed result:")
    for table in tables:
        try:
            count = db.session.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar()
            print(f"  {table}: {count}")
        except Exception:
            continue


def main():
    app = create_app()
    with app.app_context():
        ensure_chapter_compatibility()
        upsert_categories_and_tags()
        upsert_users()
        category_ids = fetch_id_map("categories")
        tag_ids = fetch_id_map("tags")
        books = build_books(category_ids)
        upsert_books(books)
        upsert_book_tags(books, tag_ids)
        upsert_reader_content(books)
        upsert_interactions(books)
        upsert_social_content(books)
        upsert_optional_moods(books)
        db.session.commit()
        print_counts()
        print(f"\nAdded or updated {len(books)} rich mock books with supporting reader data.")


if __name__ == "__main__":
    main()
