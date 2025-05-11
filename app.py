import os
from flask import Flask, render_template, request, redirect, session, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from flask import render_template

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# User 모델
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    bio = db.Column(db.String(500), nullable=True)
    is_fraud = db.Column(db.Boolean, default=False)

# Item 모델
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User')

# Comment 모델
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    user = db.relationship('User')
    children = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]))
    is_deleted = db.Column(db.Boolean, default=False)

# Chatroom 모델
class Chatroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user1 = db.relationship('User', foreign_keys=[user1_id])
    user2 = db.relationship('User', foreign_keys=[user2_id])

# Message 모델
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    chatroom_id = db.Column(db.Integer, db.ForeignKey('chatroom.id'), nullable=True)
    sender = db.relationship('User')
    chatroom = db.relationship('Chatroom')
    
# admin 계정 자동 생성
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email='admin').first():
        admin_pw = bcrypt.generate_password_hash('hi_admin').decode('utf-8')
        admin_user = User(email='admin', password=admin_pw)
        db.session.add(admin_user)
        db.session.commit()
        
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 신고한 사람
    reported_item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=True)  # 신고당한 상품
    reported_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # 신고당한 사용자
    reason = db.Column(db.Text, nullable=False)  # 신고 사유
    timestamp = db.Column(db.DateTime, default=db.func.now())  # 신고 시간

    reporter = db.relationship('User', foreign_keys=[reporter_id])
    reported_item = db.relationship('Item', foreign_keys=[reported_item_id])
    reported_user = db.relationship('User', foreign_keys=[reported_user_id])



# ---------------- Routes ----------------

@app.route('/', methods=['GET', 'POST'])
def main():
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    if request.method == 'POST':
        email = request.form['email']
        pw = request.form['password']

        # admin 아이디 예외 처리
        if email == 'admin':
            user = User.query.filter_by(email='admin').first()
        else:
            # 일반 사용자는 이메일로 로그인
            if '@' not in email:
                return '이메일 형식이 올바르지 않습니다.'
            user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, pw):
            session['user_id'] = user.id
            return redirect('/home')
        else:
            return '로그인 실패!'

    return render_template('main.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    if request.method == 'POST':
        email = request.form['email']
        pw = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(pw).decode('utf-8')
        if User.query.filter_by(email=email).first():
            return '이미 존재하는 이메일입니다.'
        new_user = User(email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/')
    return render_template('register.html')

@app.route('/home', methods=['GET', 'POST'])
def home():
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    if 'user_id' not in session:
        return redirect('/')

    search_query = request.args.get('q', '')
    if search_query:
        items = Item.query.filter(Item.name.contains(search_query)).all()
    else:
        items = Item.query.all()

    chats = Message.query.all()
    current_user = User.query.get(session.get('user_id')) if 'user_id' in session else None

    if request.method == 'POST':
        chat_text = request.form['chat'].strip()
        if chat_text:
            new_message = Message(text=chat_text, sender_id=session['user_id'])
            db.session.add(new_message)
            db.session.commit()
        return redirect(url_for('home'))

    return render_template('home.html', items=items, chats=chats, search_query=search_query, current_user=current_user)



@app.route('/upload', methods=['GET', 'POST'])
def upload():
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    if 'user_id' not in session:
        return redirect('/')
    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        desc = request.form['description']
        image = request.files['image']
        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        new_item = Item(name=name, price=price, description=desc, image=filename, user_id=session['user_id'])
        db.session.add(new_item)
        db.session.commit()
        return redirect('/home')
    return render_template('upload.html')

@app.route('/item/<int:item_id>', methods=['GET', 'POST'])
def item_detail(item_id):
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect

    item = Item.query.get_or_404(item_id)
    uploader = User.query.get(item.user_id)
    comments = Comment.query.filter_by(item_id=item_id, parent_id=None).all()
    current_user = User.query.get(session.get('user_id')) if 'user_id' in session else None

    if request.method == 'POST' and current_user:
        text = request.form['comment'].strip()
        parent_id = request.form.get('parent_id')
        if text:
            new_comment = Comment(text=text, item_id=item_id, user_id=current_user.id, parent_id=parent_id)
            db.session.add(new_comment)
            db.session.commit()
        return redirect(url_for('item_detail', item_id=item_id))

    return render_template('item.html', item=item, uploader=uploader, comments=comments, current_user=current_user)




@app.route('/edit_comment/<int:comment_id>', methods=['GET', 'POST'])
def edit_comment(comment_id):
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    comment = Comment.query.get_or_404(comment_id)
    if session['user_id'] != comment.user_id:
        abort(403)
    if request.method == 'POST':
        comment.text = request.form['text']
        db.session.commit()
        return redirect(url_for('item_detail', item_id=comment.item_id))
    return render_template('edit_comment.html', comment=comment)

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    comment = Comment.query.get_or_404(comment_id)
    if session['user_id'] != comment.user_id:
        abort(403)
    comment.is_deleted = True
    db.session.commit()
    return redirect(url_for('item_detail', item_id=comment.item_id))

@app.route('/profile', methods=['GET', 'POST'])
def my_profile():
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    if 'user_id' not in session:
        return redirect('/')

    user = User.query.get(session['user_id'])
    items = Item.query.filter_by(user_id=user.id).all()
    current_user = user

    if request.method == 'POST':
        user.bio = request.form['bio']
        if request.form['password']:
            user.password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        db.session.commit()
        return redirect(url_for('my_profile'))

    return render_template('profile.html', user=user, items=items, is_own_profile=True, current_user=current_user)


@app.route('/user/<int:user_id>')
def user_profile(user_id):
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect

    user = User.query.get_or_404(user_id)
    items = Item.query.filter_by(user_id=user.id).all()
    is_own_profile = (session.get('user_id') == user.id)
    current_user = User.query.get(session.get('user_id')) if 'user_id' in session else None

    return render_template('profile.html', user=user, items=items, is_own_profile=is_own_profile, current_user=current_user)


@app.route('/request_chat/<int:user_id>')
def request_chat(user_id):
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    if 'user_id' not in session:
        return redirect('/')
    user1_id = session['user_id']
    user2_id = user_id
    chatroom = Chatroom.query.filter(
        ((Chatroom.user1_id == user1_id) & (Chatroom.user2_id == user2_id)) |
        ((Chatroom.user1_id == user2_id) & (Chatroom.user2_id == user1_id))
    ).first()
    if not chatroom:
        chatroom = Chatroom(user1_id=user1_id, user2_id=user2_id)
        db.session.add(chatroom)
        db.session.commit()
    return redirect(url_for('chat_room', chatroom_id=chatroom.id))

@app.route('/chat_room/<int:chatroom_id>', methods=['GET', 'POST'])
def chat_room(chatroom_id):
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    if 'user_id' not in session:
        return redirect('/')
    chatroom = Chatroom.query.get_or_404(chatroom_id)
    messages = Message.query.filter_by(chatroom_id=chatroom_id).all()
    if request.method == 'POST':
        message_text = request.form['message']
        new_message = Message(text=message_text, sender_id=session['user_id'], chatroom_id=chatroom_id)
        db.session.add(new_message)
        db.session.commit()
        return redirect(url_for('chat_room', chatroom_id=chatroom_id))
    return render_template('chat_room.html', chatroom=chatroom, messages=messages)

@app.route('/my_chats')
def my_chats():
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    if 'user_id' not in session:
        return redirect('/')
    user_id = session['user_id']
    chatrooms = Chatroom.query.filter(
        (Chatroom.user1_id == user_id) | (Chatroom.user2_id == user_id)
    ).all()
    return render_template('my_chats.html', chatrooms=chatrooms)

@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
def edit_item(item_id):
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    item = Item.query.get_or_404(item_id)
    user = User.query.get(session['user_id'])

    # admin은 모든 글 수정 가능, 일반 유저는 자기 글만 가능
    if user.email != 'admin' and session['user_id'] != item.user_id:
        abort(403)

    if request.method == 'POST':
        item.name = request.form['name']
        item.price = request.form['price']
        item.description = request.form['description']
        db.session.commit()
        return redirect(url_for('item_detail', item_id=item.id))
    
    return render_template('edit_item.html', item=item)

@app.route('/delete_item/<int:item_id>', methods=['POST'])
def delete_item(item_id):
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    item = Item.query.get_or_404(item_id)
    user = User.query.get(session['user_id'])

    # admin은 모든 글 삭제 가능, 일반 유저는 자기 글만 가능
    if user.email != 'admin' and session['user_id'] != item.user_id:
        abort(403)

    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/report_item/<int:item_id>', methods=['GET', 'POST'])
def report_item(item_id):
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    if 'user_id' not in session:
        return redirect('/')

    item = Item.query.get_or_404(item_id)

    if request.method == 'POST':
        reason = request.form['reason']
        new_report = Report(reporter_id=session['user_id'], reported_item_id=item.id, reason=reason)
        db.session.add(new_report)
        db.session.commit()
        return redirect(url_for('home'))

    return render_template('report_form.html', target='상품', target_name=item.name)

@app.route('/report_user/<int:user_id>', methods=['GET', 'POST'])
def report_user(user_id):
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    if 'user_id' not in session:
        return redirect('/')

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        reason = request.form['reason']
        new_report = Report(reporter_id=session['user_id'], reported_user_id=user.id, reason=reason)
        db.session.add(new_report)
        db.session.commit()
        return redirect(url_for('home'))

    return render_template('report_form.html', target='사용자', target_name=user.email)

@app.route('/reports')
def reports():
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    if 'user_id' not in session:
        return redirect('/')

    current_user = User.query.get(session['user_id'])
    if current_user.email != 'admin':
        abort(403)

    reports = Report.query.order_by(Report.timestamp.desc()).all()
    fraud_users = User.query.filter_by(is_fraud=True).all()

    return render_template('reports.html', reports=reports, fraud_users=fraud_users)


def check_fraud_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.is_fraud:
            return redirect(url_for('fraud_user'))
    return None

@app.route('/fraud_user')
def fraud_user():
    return render_template('fraud_user.html')

@app.route('/mark_fraud_user/<int:user_id>', methods=['POST'])
def mark_fraud_user(user_id):
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    if 'user_id' not in session:
        return redirect('/')
    
    current_user = User.query.get(session['user_id'])
    if current_user.email != 'admin':
        abort(403)

    user = User.query.get_or_404(user_id)
    user.is_fraud = True
    db.session.commit()
    return redirect(url_for('user_profile', user_id=user.id))

@app.route('/restore_user/<int:user_id>', methods=['POST'])
def restore_user(user_id):
    fraud_redirect = check_fraud_user()
    if fraud_redirect:
        return fraud_redirect
    if 'user_id' not in session:
        return redirect('/')
    
    current_user = User.query.get(session['user_id'])
    if current_user.email != 'admin':
        abort(403)

    user = User.query.get_or_404(user_id)
    user.is_fraud = False
    db.session.commit()
    return redirect(url_for('user_profile', user_id=user.id))






@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)