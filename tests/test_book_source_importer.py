import json
import unittest

from app.services.book_source_importer import (
    BookCandidate,
    extract_book_candidates,
    extract_source_json_from_page,
    parse_book_info,
    parse_chapter_content,
    parse_chapters,
    parse_word_count,
    _normalize_source_location,
)


class BookSourceImporterParsingTestCase(unittest.TestCase):
    def test_normalize_source_content_page_to_json_url(self):
        self.assertEqual(
            _normalize_source_location('https://www.yckceo.com/yuedu/shuyuan/content/id/7254.html'),
            'https://www.yckceo.com/yuedu/shuyuan/json/id/7254.json',
        )

    def test_extract_source_json_from_page(self):
        payload = {'bookSourceName': '测试书源', 'bookSourceUrl': 'https://example.test'}
        page = f'<html><pre class="layui-code" id="jsonpre">{json.dumps(payload, ensure_ascii=False)}</pre></html>'

        self.assertEqual(json.loads(extract_source_json_from_page(page))['bookSourceName'], '测试书源')

    def test_extract_book_candidates(self):
        page = '''
            <a href="/book/100.html">第一本书</a>
            <a href="https://www.biquge.tw/book/101.html">第二本书</a>
            <a href="/book/100.html">第一本书</a>
        '''

        items = extract_book_candidates(page, base_url='https://www.biquge.tw', source_category_path='/sort/')

        self.assertEqual([item.title for item in items], ['第一本书', '第二本书'])
        self.assertEqual(items[0].url, 'https://www.biquge.tw/book/100.html')

    def test_parse_book_info(self):
        page = '''
            <h1>星河旧梦</h1>
            <h2>作者：青山&nbsp; 字数：123.4万 <span><a>青山</a></span></h2>
            <div class="cover"><img src="/covers/star.jpg"></div>
            <div class="intro"><p>一段星际旅程。</p></div>
            <a href="/sort/kehuan/">科幻</a>
            <p>最新章节 <a>第十章 归航</a></p>
            <a href="/book/100/" class="chapterlist">章节目录</a>
        '''

        info = parse_book_info(
            page,
            BookCandidate(title='星河旧梦', url='https://www.biquge.tw/book/100.html', source_category_path='/sort/kehuan/'),
            base_url='https://www.biquge.tw',
        )

        self.assertEqual(info.title, '星河旧梦')
        self.assertEqual(info.author, '青山')
        self.assertEqual(info.cover, 'https://www.biquge.tw/covers/star.jpg')
        self.assertEqual(info.category_code, 'scifi')
        self.assertEqual(info.word_count, 1234000)
        self.assertEqual(info.toc_url, 'https://www.biquge.tw/book/100/')

    def test_parse_chapters_and_content(self):
        toc = '''
            <div class="booklist"><ul>
              <li><a href="/book/100/1.html">第一章</a></li>
              <li><a href="/book/100/2.html">第二章</a></li>
            </ul></div>
            <a href="/book/100.html">书籍详情</a>
        '''
        content = '<div id="chaptercontent">第一段。<br><br>第二段。请收藏本站 www.example.test</div>'

        chapters = parse_chapters(toc, base_url='https://www.biquge.tw')

        self.assertEqual(len(chapters), 2)
        self.assertEqual(chapters[1].url, 'https://www.biquge.tw/book/100/2.html')
        self.assertEqual(parse_chapter_content(content), '第一段。\n\n第二段。')

    def test_parse_word_count_units(self):
        self.assertEqual(parse_word_count('字数：12万'), 120000)
        self.assertEqual(parse_word_count('8.5千'), 8500)
        self.assertEqual(parse_word_count('900'), 900)


if __name__ == '__main__':
    unittest.main()
