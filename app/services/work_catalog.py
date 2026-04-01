WORK_CATEGORY_TAXONOMY = [
    {
        'code': 'fantasy',
        'name': '玄幻',
        'subcategories': [
            {'code': 'eastern_fantasy', 'name': '东方玄幻'},
            {'code': 'western_fantasy', 'name': '西方奇幻'},
            {'code': 'xianxia', 'name': '仙侠修真'},
        ],
        'tag_codes': ['chosen_one', 'leveling', 'sect', 'beast_taming', 'treasure_hunt', 'hot_blooded'],
    },
    {
        'code': 'romance',
        'name': '言情',
        'subcategories': [
            {'code': 'ancient_romance', 'name': '古代言情'},
            {'code': 'modern_romance', 'name': '现代言情'},
            {'code': 'campus_romance', 'name': '校园甜宠'},
        ],
        'tag_codes': ['sweet_love', 'marriage_first', 'redemption', 'double_cleansing', 'career_woman', 'healing'],
    },
    {
        'code': 'urban',
        'name': '都市',
        'subcategories': [
            {'code': 'modern_city', 'name': '现代都市'},
            {'code': 'workplace', 'name': '职场商战'},
            {'code': 'supernatural_city', 'name': '都市异能'},
        ],
        'tag_codes': ['workplace', 'counterattack', 'rich_family', 'daily_life', 'system', 'comedy'],
    },
    {
        'code': 'history',
        'name': '历史',
        'subcategories': [
            {'code': 'overhead_history', 'name': '架空历史'},
            {'code': 'war_strategy', 'name': '权谋战争'},
            {'code': 'officialdom', 'name': '朝堂官场'},
        ],
        'tag_codes': ['power_struggle', 'nation_building', 'warfare', 'strategy', 'time_travel', 'court'],
    },
    {
        'code': 'suspense',
        'name': '悬疑',
        'subcategories': [
            {'code': 'mystery', 'name': '推理探案'},
            {'code': 'horror', 'name': '惊悚灵异'},
            {'code': 'crime', 'name': '刑侦罪案'},
        ],
        'tag_codes': ['inference', 'crime', 'mind_game', 'reverse', 'horror', 'survival'],
    },
    {
        'code': 'scifi',
        'name': '科幻',
        'subcategories': [
            {'code': 'future_world', 'name': '未来世界'},
            {'code': 'interstellar', 'name': '星际文明'},
            {'code': 'post_apocalypse', 'name': '末日废土'},
        ],
        'tag_codes': ['mecha', 'starfield', 'apocalypse', 'ai', 'hard_scifi', 'time_space'],
    },
]

WORK_TAG_LIBRARY = [
    {'code': 'chosen_one', 'label': '天命主角'},
    {'code': 'leveling', 'label': '升级流'},
    {'code': 'sect', 'label': '宗门'},
    {'code': 'beast_taming', 'label': '御兽'},
    {'code': 'treasure_hunt', 'label': '寻宝'},
    {'code': 'hot_blooded', 'label': '热血'},
    {'code': 'sweet_love', 'label': '甜宠'},
    {'code': 'marriage_first', 'label': '先婚后爱'},
    {'code': 'redemption', 'label': '救赎'},
    {'code': 'double_cleansing', 'label': '双洁'},
    {'code': 'career_woman', 'label': '大女主'},
    {'code': 'healing', 'label': '治愈'},
    {'code': 'workplace', 'label': '职场'},
    {'code': 'counterattack', 'label': '逆袭'},
    {'code': 'rich_family', 'label': '豪门'},
    {'code': 'daily_life', 'label': '日常'},
    {'code': 'system', 'label': '系统'},
    {'code': 'comedy', 'label': '轻喜剧'},
    {'code': 'power_struggle', 'label': '权谋'},
    {'code': 'nation_building', 'label': '建设'},
    {'code': 'warfare', 'label': '战争'},
    {'code': 'strategy', 'label': '智斗'},
    {'code': 'time_travel', 'label': '穿越'},
    {'code': 'court', 'label': '朝堂'},
    {'code': 'inference', 'label': '推理'},
    {'code': 'crime', 'label': '刑侦'},
    {'code': 'mind_game', 'label': '心理博弈'},
    {'code': 'reverse', 'label': '反转'},
    {'code': 'horror', 'label': '惊悚'},
    {'code': 'survival', 'label': '生存'},
    {'code': 'mecha', 'label': '机甲'},
    {'code': 'starfield', 'label': '星际'},
    {'code': 'apocalypse', 'label': '末世'},
    {'code': 'ai', 'label': '人工智能'},
    {'code': 'hard_scifi', 'label': '硬科幻'},
    {'code': 'time_space', 'label': '时空'},
]

WORK_CATEGORY_MAP = {item['code']: item for item in WORK_CATEGORY_TAXONOMY}
WORK_TAG_MAP = {item['code']: item for item in WORK_TAG_LIBRARY}


def get_subcategories(category_code: str | None):
    if not category_code:
        return []
    return list(WORK_CATEGORY_MAP.get(category_code, {}).get('subcategories', []))


def get_category_tag_codes(category_code: str | None):
    if not category_code:
        return []
    return list(WORK_CATEGORY_MAP.get(category_code, {}).get('tag_codes', []))

