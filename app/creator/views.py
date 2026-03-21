import os
from datetime import datetime
from uuid import uuid4

from flask import current_app, jsonify, request
from werkzeug.utils import secure_filename

from app import db
from app.creator import bp
from app.models import Book, BookManuscript
from app.rbac.decorators import login_required

ALLOWED_COVER_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp'}


def _is_creator(user):
    return user and user.role in ('creator', 'admin')


def _extract_extension(filename: str):
    return (filename.rsplit('.', 1)[-1].lower() if '.' in (filename or '') else '')


def _save_cover_file(file_obj):
    if not file_obj:
        return None, None

    filename = file_obj.filename or ''
    ext = _extract_extension(filename)
    if ext not in ALLOWED_COVER_EXTENSIONS:
        return None, 'cover file type not allowed'

    file_obj.stream.seek(0, os.SEEK_END)
    size = file_obj.stream.tell()
    file_obj.stream.seek(0)
    max_size = int(current_app.config.get('MAX_COVER_UPLOAD_SIZE', 5 * 1024 * 1024))
    if size > max_size:
        return None, 'cover file too large'

    safe_name = secure_filename(filename)
    _, safe_ext = os.path.splitext(safe_name)
    final_name = f'{uuid4().hex}{safe_ext.lower()}'

    upload_root = current_app.config.get('UPLOAD_DIR', os.path.join('instance', 'uploads'))
    subdir = current_app.config.get('COVER_UPLOAD_SUBDIR', 'book_covers')
    abs_dir = os.path.join(upload_root, subdir)
    os.makedirs(abs_dir, exist_ok=True)
    abs_path = os.path.join(abs_dir, final_name)
    file_obj.save(abs_path)

    return f'/uploads/{subdir}/{final_name}', None


def _extract_payload():
    if request.content_type and 'multipart/form-data' in request.content_type.lower():
        form = request.form
        files = request.files
        cover, error = _save_cover_file(files.get('cover_file'))
        if error:
            return None, error
        content_text = (form.get('content_text') or '').strip()
        content_file = files.get('content_file')
        if not content_text and content_file:
            raw = content_file.read()
            content_text = raw.decode('utf-8', errors='ignore').strip()
        data = {
            'book_id': form.get('book_id'),
            'title': (form.get('title') or '').strip(),
            'description': (form.get('description') or '').strip() or None,
            'cover': cover or (form.get('cover') or '').strip() or None,
            'content_text': content_text or None,
        }
        return data, None

    data = request.get_json() or {}
    return {
        'book_id': data.get('book_id'),
        'title': (data.get('title') or '').strip(),
        'description': (data.get('description') or '').strip() or None,
        'cover': (data.get('cover') or '').strip() or None,
        'content_text': (data.get('content_text') or '').strip() or None,
    }, None


@bp.route('/manuscripts', methods=['GET'])
@login_required
def list_creator_manuscripts(current_user):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    status = (request.args.get('status') or '').strip()
    query = BookManuscript.query.filter_by(creator_id=current_user.id)
    if status:
        query = query.filter_by(status=status)
    rows = query.order_by(BookManuscript.updated_at.desc(), BookManuscript.id.desc()).all()
    return jsonify({'items': [row.to_dict() for row in rows]}), 200


@bp.route('/manuscripts', methods=['POST'])
@login_required
def create_creator_manuscript(current_user):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    payload, error = _extract_payload()
    if error:
        return jsonify({'error': error}), 400

    title = payload.get('title')
    if not title:
        return jsonify({'error': 'title is required'}), 400

    book_id = payload.get('book_id')
    book = None
    if book_id not in (None, ''):
        try:
            book_id = int(book_id)
        except (TypeError, ValueError):
            return jsonify({'error': 'invalid book_id'}), 400
        book = Book.query.get(book_id)
        if not book:
            return jsonify({'error': 'book not found'}), 404
        if book.creator_id not in (None, current_user.id) and not current_user.is_admin():
            return jsonify({'error': 'cannot edit this book'}), 403
    else:
        book = Book(
            title=title,
            description=payload.get('description'),
            cover=payload.get('cover'),
            status='draft',
            creator_id=current_user.id,
            created_at=datetime.utcnow(),
        )
        db.session.add(book)
        db.session.flush()

    manuscript = BookManuscript(
        book_id=book.id,
        creator_id=current_user.id,
        title=title,
        cover=payload.get('cover'),
        description=payload.get('description'),
        content_text=payload.get('content_text'),
        status='draft',
    )
    db.session.add(manuscript)
    db.session.commit()
    return jsonify({'message': 'draft created', 'manuscript': manuscript.to_dict()}), 201


@bp.route('/manuscripts/<int:manuscript_id>', methods=['PUT'])
@login_required
def update_creator_manuscript(current_user, manuscript_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    manuscript = BookManuscript.query.get(manuscript_id)
    if not manuscript:
        return jsonify({'error': 'manuscript not found'}), 404
    if manuscript.creator_id != current_user.id and not current_user.is_admin():
        return jsonify({'error': 'cannot edit this manuscript'}), 403
    if manuscript.status not in ('draft', 'rejected'):
        return jsonify({'error': 'only draft/rejected manuscript can be edited'}), 400

    payload, error = _extract_payload()
    if error:
        return jsonify({'error': error}), 400

    if 'title' in payload and payload.get('title'):
        manuscript.title = payload['title']
    if 'cover' in payload and payload.get('cover') is not None:
        manuscript.cover = payload.get('cover')
    if 'description' in payload:
        manuscript.description = payload.get('description')
    if 'content_text' in payload and payload.get('content_text') is not None:
        manuscript.content_text = payload.get('content_text')

    manuscript.status = 'draft'
    manuscript.review_comment = None

    db.session.commit()
    return jsonify({'message': 'draft updated', 'manuscript': manuscript.to_dict()}), 200


@bp.route('/manuscripts/<int:manuscript_id>/submit', methods=['POST'])
@login_required
def submit_creator_manuscript(current_user, manuscript_id: int):
    if not _is_creator(current_user):
        return jsonify({'error': 'creator role required'}), 403

    manuscript = BookManuscript.query.get(manuscript_id)
    if not manuscript:
        return jsonify({'error': 'manuscript not found'}), 404
    if manuscript.creator_id != current_user.id and not current_user.is_admin():
        return jsonify({'error': 'cannot submit this manuscript'}), 403
    if manuscript.status not in ('draft', 'rejected'):
        return jsonify({'error': 'manuscript status cannot submit'}), 400
    if not (manuscript.title or '').strip():
        return jsonify({'error': 'title is required'}), 400
    if not (manuscript.content_text or '').strip():
        return jsonify({'error': 'content_text is required'}), 400

    manuscript.status = 'submitted'
    manuscript.submitted_at = datetime.utcnow()
    manuscript.review_comment = None
    db.session.commit()
    return jsonify({'message': 'manuscript submitted', 'manuscript': manuscript.to_dict()}), 200
