import unittest
from types import SimpleNamespace

from scripts.auto_tag_books import (
    BookTagContext,
    latest_chapter_from_update_note,
    match_tags,
    parse_book_ids,
)


class AutoTagBooksTestCase(unittest.TestCase):
    def test_match_tags_from_title_description_category_latest_and_keywords(self):
        available_tags = {
            code: SimpleNamespace(id=index, code=code, label=label)
            for index, (code, label) in enumerate(
                [
                    ('system', '系统'),
                    ('counterattack', '逆袭'),
                    ('workplace', '职场'),
                    ('sweet_love', '甜宠'),
                    ('healing', '治愈'),
                    ('comedy', '轻喜剧'),
                ],
                start=1,
            )
        }
        context = BookTagContext(
            book_id=1,
            title='职场逆袭系统',
            description='主角在公司项目中一路反击，故事轻松治愈。',
            source_category='urban 都市 workplace',
            latest_chapter='第42章 新任务奖励',
            search_keywords='创业 职场 系统 打脸',
            category_code='urban',
        )

        matches = match_tags(context, available_tags, max_tags=4)
        codes = [item.code for item in matches]

        self.assertIn('system', codes)
        self.assertIn('workplace', codes)
        self.assertIn('counterattack', codes)
        self.assertLessEqual(len(codes), 4)

    def test_category_defaults_do_not_create_tags_without_text_evidence(self):
        available_tags = {
            code: SimpleNamespace(id=index, code=code, label=label)
            for index, (code, label) in enumerate(
                [
                    ('workplace', '职场'),
                    ('counterattack', '逆袭'),
                    ('rich_family', '豪门'),
                    ('daily_life', '日常'),
                    ('system', '系统'),
                    ('comedy', '轻喜剧'),
                ],
                start=1,
            )
        }
        context = BookTagContext(
            book_id=2,
            title='城市晚风',
            description='一段平静的城市故事。',
            source_category='urban 都市',
            category_code='urban',
        )

        self.assertEqual(match_tags(context, available_tags), [])

    def test_broad_essay_keyword_requires_stronger_evidence(self):
        available_tags = {
            'essay': SimpleNamespace(id=1, code='essay', label='散文'),
            'healing': SimpleNamespace(id=2, code='healing', label='治愈'),
        }
        context = BookTagContext(
            book_id=3,
            title='小村医的强悍人生',
            description='主角回到村里开始新的生活。',
            search_keywords='乡村 医生 人生',
        )

        self.assertEqual(match_tags(context, available_tags), [])

    def test_parse_book_ids(self):
        self.assertEqual(parse_book_ids('1, 2,,3'), [1, 2, 3])
        self.assertEqual(parse_book_ids(''), [])

    def test_latest_chapter_from_update_note(self):
        self.assertEqual(
            latest_chapter_from_update_note('外部来源：https://example.test；最后章节：第九章 破局'),
            '第九章 破局',
        )
        self.assertEqual(latest_chapter_from_update_note('最后章节：未获取'), '')


if __name__ == '__main__':
    unittest.main()
