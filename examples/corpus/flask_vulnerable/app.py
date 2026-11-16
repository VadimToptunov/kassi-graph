"""Test corpus — Flask app with a known IDOR and a guarded counterexample.

Expected:
  - `user_details` (no auth check) → FINDING (BOLA on User.query.get)
  - `my_profile` (uses current_user implicitly, no param) → NO FINDING
  - `delete_user` (guarded by login_required + role check) → NO FINDING
"""
from flask import Flask, jsonify, request
from flask_login import login_required, current_user

from .models import db, User, Post

app = Flask(__name__)


@app.route('/api/users/<int:user_id>', methods=['GET'])
def user_details(user_id):
    """BOLA/IDOR — any caller can fetch any user by id, no ownership check."""
    user = User.query.get(user_id)
    return jsonify({'id': user.id, 'email': user.email})


@app.route('/api/me', methods=['GET'])
@login_required
def my_profile():
    """Guarded — returns only current_user. No user_id param."""
    return jsonify({'id': current_user.id, 'email': current_user.email})


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    """Guarded — checks admin role AND passes through login_required."""
    if not current_user.has_role('admin'):
        return jsonify({'error': 'forbidden'}), 403
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'ok': True})


@app.route('/api/posts/<int:post_id>', methods=['GET'])
def get_post(post_id):
    """Guarded by naming convention — public posts are intentionally readable."""
    post = Post.query.get(post_id)
    return jsonify({'id': post.id, 'title': post.title, 'body': post.body})


@app.route('/api/posts/<int:post_id>', methods=['PATCH'])
@login_required
def edit_post(post_id):
    """Vulnerable — login_required protects auth but ownership is NOT checked."""
    post = Post.query.get(post_id)
    body = request.get_json()
    post.title = body.get('title', post.title)
    post.body = body.get('body', post.body)
    db.session.commit()
    return jsonify({'ok': True})
