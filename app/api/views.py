from flask import jsonify, request

from app.api import bp
from app.rbac.decorators import login_required


@bp.route('/user/profile', methods=['GET'])
@login_required
def api_get_user_profile(current_user):
    """
    获取当前登录用户信息（首页顶部展示用）
    """
    # 这里直接复用 User.to_dict，并额外返回一个示例性的 book_age_days 字段
    user_data = current_user.to_dict()
    user_data['book_age_days'] = 1240
    return jsonify(user_data), 200


@bp.route('/notifications/unread-count', methods=['GET'])
@login_required
def api_get_unread_notifications_count(current_user):
    """
    获取未读通知数量
    """
    # 目前先返回一个固定值，后续可以接入真实通知表
    return jsonify({'unread_count': 3}), 200


@bp.route('/books/search', methods=['GET'])
def api_search_books():
    """
    全局搜索图书
    """
    q = request.args.get('q', '').strip()
    # 目前先返回示例数据，后续可接入真实 Book 模型和搜索逻辑
    return jsonify({
        'items': [
            {
                'id': 101,
                'title': '夜晚的潜水艇',
                'author': '陈春成',
                'cover': 'https://example.com/covers/night.jpg',
                'rating': 9.1,
            }
        ]
    }), 200


@bp.route('/books/featured', methods=['GET'])
def api_get_featured_book():
    """
    获取当前主推图书（Hero 区域）
    """
    return jsonify({
        'id': 201,
        'title': '漫长的余生',
        'subtitle': '在《漫长的余生》中重构历史的涟漪',
        'author': '罗新',
        'description': '这不是一部高头讲章式的史学著作，而是……',
        'cover': 'https://example.com/covers/featured.jpg',
        'score': 9.4,
        'recent_reads': 128000,
    }), 200


@bp.route('/shelf', methods=['POST'])
@login_required
def api_add_to_shelf(current_user):
    """
    将图书加入书架（包括 Hero 区域“加入书架”）
    """
    data = request.get_json() or {}
    book_id = data.get('book_id')
    if not book_id:
        return jsonify({'error': '缺少 book_id'}), 400

    # 这里暂时不落库，只返回成功状态，后续可接入 UserBookShelf 模型
    return jsonify({'message': '已加入书架', 'book_id': book_id}), 200


@bp.route('/books/<int:book_id>/preview', methods=['GET'])
def api_get_book_preview(book_id: int):
    """
    获取试读内容链接/章节
    """
    return jsonify({
        'preview_url': f'https://example.com/reader?book={book_id}',
        'chapters': [
            {'id': 1, 'title': '第一章'},
        ],
    }), 200


@bp.route('/moods', methods=['GET'])
def api_get_moods():
    """
    获取可选心境标签列表
    """
    return jsonify({
        'items': [
            {'id': 'healing', 'label': '寻求治愈', 'icon': 'hugeicons:cloud-01'},
            {'id': 'brainstorm', 'label': '脑力风暴', 'icon': 'hugeicons:flash'},
            {'id': 'focus', 'label': '深度专注', 'icon': 'hugeicons:target-02'},
        ]
    }), 200


@bp.route('/recommendations/by-mood', methods=['GET'])
def api_get_recommendations_by_mood():
    """
    按心境推荐图书
    """
    mood_id = request.args.get('mood_id', 'healing')
    return jsonify({
        'mood_id': mood_id,
        'books': [
            {
                'id': 301,
                'title': '治愈系小说 A',
                'author': '某作者',
                'cover': 'https://example.com/covers/healing-a.jpg',
                'rating': 8.9,
            }
        ],
    }), 200


@bp.route('/recommendations/personalized', methods=['GET'])
@login_required
def api_get_personalized_recommendations(current_user):
    """
    获取首页个性化推荐书单
    """
    return jsonify({
        'items': [
            {
                'id': 401,
                'title': '夜晚的潜水艇',
                'author': '陈春成',
                'cover': 'https://example.com/covers/night.jpg',
                'rating': 9.1,
                'rating_count': 12000,
            }
        ]
    }), 200


@bp.route('/shelf/toggle', methods=['POST'])
@login_required
def api_toggle_shelf(current_user):
    """
    加入/移除书架
    """
    data = request.get_json() or {}
    book_id = data.get('book_id')
    in_shelf = data.get('in_shelf')
    if book_id is None or in_shelf is None:
        return jsonify({'error': '缺少 book_id 或 in_shelf'}), 400

    action = 'added' if in_shelf else 'removed'
    return jsonify({'message': f'书架已{action}', 'book_id': book_id, 'in_shelf': in_shelf}), 200


@bp.route('/recommendations/feedback', methods=['POST'])
@login_required
def api_recommendation_feedback(current_user):
    """
    标记「不再推荐」/「不感兴趣」等推荐反馈
    """
    data = request.get_json() or {}
    book_id = data.get('book_id')
    action = data.get('action')
    if not book_id or not action:
        return jsonify({'error': '缺少 book_id 或 action'}), 400

    return jsonify({'message': '反馈已记录', 'book_id': book_id, 'action': action}), 200


@bp.route('/books/rankings', methods=['GET'])
def api_get_book_rankings():
    """
    获取高分口碑榜等榜单
    """
    rank_type = request.args.get('type', 'high_score')
    try:
        limit = int(request.args.get('limit', '10'))
    except ValueError:
        limit = 10

    items = [
        {
            'rank': 1,
            'id': 501,
            'title': '额尔古纳河右岸',
            'author': '迟子建',
            'cover': 'https://example.com/covers/rank1.jpg',
            'rating': 9.5,
            'rating_count': 124000,
        }
    ][:limit]

    return jsonify({'type': rank_type, 'items': items}), 200


@bp.route('/user/weekly-reading-task', methods=['GET'])
@login_required
def api_get_weekly_reading_task(current_user):
    """
    获取当前用户本周阅读任务
    """
    return jsonify({
        'target_books': 5,
        'finished_books': 3,
        'progress_percent': 60,
        'reward_desc': '完成后可领取「春季限定书签」',
    }), 200


@bp.route('/user/weekly-reading-task/progress', methods=['POST'])
@login_required
def api_update_weekly_reading_progress(current_user):
    """
    更新本周阅读任务进度
    """
    data = request.get_json() or {}
    finished_books = data.get('finished_books')
    if finished_books is None:
        return jsonify({'error': '缺少 finished_books'}), 400

    # 这里暂时不做真实计算，只是根据 finished_books 返回一个简单进度
    target = 5
    progress_percent = max(0, min(100, int(finished_books / target * 100))) if target else 0

    return jsonify({
        'target_books': target,
        'finished_books': finished_books,
        'progress_percent': progress_percent,
        'reward_desc': '完成后可领取「春季限定书签」',
    }), 200


@bp.route('/categories/highlighted', methods=['GET'])
def api_get_highlighted_categories():
    """
    获取推荐分类列表（四个大卡片）
    """
    return jsonify({
        'items': [
            {
                'id': 'cyber_folk',
                'name': '赛博民俗',
                'en_name': 'Sci-Fi',
                'description': '当芯片遇见古老传说',
                'cover': 'https://example.com/covers/cate1.jpg',
            }
        ]
    }), 200


@bp.route('/tags/hot', methods=['GET'])
def api_get_hot_tags():
    """
    获取热门题材标签云
    """
    return jsonify({
        'items': [
            {'id': 'hard_mystery', 'label': '硬核推理'},
            {'id': 'feminism', 'label': '女性主义'},
        ]
    }), 200


@bp.route('/books/by-category', methods=['GET'])
def api_get_books_by_category_or_tag():
    """
    按分类或标签获取图书列表
    """
    category_id = request.args.get('category_id')
    tag_id = request.args.get('tag_id')

    if not category_id and not tag_id:
        return jsonify({'error': '需要提供 category_id 或 tag_id'}), 400

    return jsonify({
        'category_id': category_id,
        'tag_id': tag_id,
        'items': [
            {
                'id': 601,
                'title': '分类/标签示例图书',
                'author': '某作者',
                'cover': 'https://example.com/covers/cate-tag.jpg',
                'rating': 8.7,
            }
        ],
    }), 200


@bp.route('/reviews/highlighted', methods=['GET'])
def api_get_highlighted_reviews():
    """
    获取首页精选书评列表
    """
    return jsonify({
        'items': [
            {
                'id': 701,
                'user': {
                    'id': 10,
                    'nickname': '木心追随者',
                    'avatar': 'https://example.com/avatars/user1.jpg',
                },
                'book': {
                    'id': 401,
                    'title': '文学回忆录',
                },
                'content': '读这本书就像是在听一位老者在烛光下缓缓讲述……',
                'likes': 1200,
                'comments': 82,
                'created_at': '2026-03-15',
            }
        ]
    }), 200


@bp.route('/reviews/<int:review_id>/like', methods=['POST'])
@login_required
def api_like_review(current_user, review_id: int):
    """
    点赞书评
    """
    data = request.get_json() or {}
    like = data.get('like', True)

    return jsonify({
        'message': '操作成功',
        'review_id': review_id,
        'like': like,
    }), 200


@bp.route('/reviews/<int:review_id>/comments', methods=['POST'])
@login_required
def api_comment_on_review(current_user, review_id: int):
    """
    对书评发表评论
    """
    data = request.get_json() or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': '评论内容不能为空'}), 400

    # 暂时返回一个示例 comment_id，后续可接入真实评论表
    return jsonify({
        'message': '评论成功',
        'review_id': review_id,
        'comment': {
            'id': 1,
            'user_id': current_user.id,
            'content': content,
        }
    }), 201

