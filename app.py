from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import pytz
from markupsafe import escape
import os
from flask_socketio import SocketIO, emit
from markupsafe import Markup
from flask_socketio import join_room, leave_room
from flask import session
import logging
import time
from flask_login import LoginManager
from flask_login import login_user
from flask_login import logout_user
from flask_login import login_required
from flask_login import current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import hashlib

# Loggingの設定
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
socketio = SocketIO(app, manage_session=True, ping_timeout=600, ping_interval=10, cors_allowed_origins="*")

#データベース構築
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://site9user:140286TakaHiro@localhost/site9db_2'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://site9user:140286TakaHiro@db/site9db_2'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

entry_table = db.Table('entry_table',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('room_id', db.Integer, db.ForeignKey('room.id'), primary_key=True),
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    nickname = db.Column(db.Text(), nullable=False)
    password = db.Column(db.Text(), nullable=False)
    rooms = db.relationship('Room', secondary=entry_table, backref=db.backref('users', lazy=True))
    conversations = db.relationship('Conversation', backref='user')

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    room_name = db.Column(db.Text(), nullable=False)
    room_password = db.Column(db.Text(), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    conversations = db.relationship('Conversation', backref='room')

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    content = db.Column(db.Text(), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)

#############################################
#ログイン設定
app.config['SECRET_KEY'] = 'hiroki-secret-key'

limiter = Limiter(get_remote_address, app=app, default_limits=["30 per minute"])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def hash_password(password):
    hash_object = hashlib.sha256()
    hash_object.update(password.encode('utf-8'))
    hashed_password = hash_object.hexdigest()
    return hashed_password

def get_nickname():
    if current_user.is_authenticated:
        nickname = current_user.nickname
    else:
        nickname = "ログインしていません"
    return nickname

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("30/minute") 
def login():
    nickname=get_nickname()
    if request.method == 'POST':
        #認証
        user = User.query.filter_by(nickname=request.form['nickname']).first()
        if user and user.password == hash_password(request.form['password']):
            login_user(user)
            return redirect(url_for('home'))
        else:
            good_or_bad="nicknameかpasswordが間違っています。"
    elif request.method == 'GET':
        good_or_bad="チャットを始めるにはログインが必要です"
    return render_template('login.html', good_or_bad=good_or_bad, nickname=nickname)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    nickname=get_nickname()
    if request.method == 'POST':
        # サインアップ
        user = User.query.filter_by(nickname=request.form['nickname']).first()
        if user:
            already_used_or_not='すでに使われているnicknameです'
        else:
            #Userテーブルへ
            nickname = request.form['nickname']
            hashed_password = hash_password(request.form['password'])
            new_user = User(nickname=nickname, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
    elif request.method == 'GET':
        already_used_or_not='他のサービスで使っているパスワードや名前などは絶対に使用しないでください。'
    return render_template('signup.html', already_used_or_not=already_used_or_not, nickname=nickname)

#############################################
#補助の関数
def preprocess_user_input(input_string):
    processed_string = str(escape(input_string)).replace('\n', '<br>')
    return processed_string

def conversation_post(timestamp, content, user_id, room_id):
    conversation=Conversation(timestamp=timestamp, content=content, user_id=user_id, room_id=room_id)
    db.session.add(conversation)
    db.session.commit()

#############################################
#メインの関数
@app.route('/', methods=['GET', 'POST'])
def home():
    nickname=get_nickname()
    login_true_or_false=False
    rooms_with_creatornicknames_entryusers=None
    roomid_password_wrong_or_not=''
    if current_user.is_authenticated:
        if request.method == 'POST' and "new_room_name" in request.form:
            room_name=request.form["new_room_name"]
            room_password=request.form["new_room_password"]
            room_password2=request.form["new_room_password2"]
            if room_password==room_password2:
                room=Room(room_name=room_name, room_password=hash_password(room_password), creator_id=current_user.id)
                db.session.add(room)
                db.session.commit()
                user = User.query.get(current_user.id)
                user.rooms.append(room)
                db.session.commit()
            else:
                roomid_password_wrong_or_not="Room IDかPasswordが間違っています"
        elif request.method == 'POST' and "enter_room_id" in request.form:
            enter_room_id=request.form["enter_room_id"]
            enter_room_password=request.form["enter_room_password"]
            room = Room.query.get(enter_room_id)
            user = User.query.get(current_user.id)
            if room and hash_password(enter_room_password)==Room.query.get(enter_room_id).room_password:
                if room not in user.rooms:
                    user.rooms.append(room)
                    db.session.commit()
                else:
                    roomid_password_wrong_or_not="そのRoomにはすでにentryしています"
            else:
                roomid_password_wrong_or_not="Room IDかPasswordが間違っています"
        login_true_or_false=True
        rooms = current_user.rooms
        rooms_with_creatornicknames_entryusers=[(room, User.query.get(room.creator_id).nickname, [user.nickname for user in room.users]) for room in rooms]
    return render_template('home.html', rooms_with_creatornicknames_entryusers=rooms_with_creatornicknames_entryusers, nickname=nickname, login_true_or_false=login_true_or_false, roomid_password_wrong_or_not=roomid_password_wrong_or_not)

@app.route('/thread/<int:thread_id>', methods=['GET', 'POST'])
@login_required
def view_thread(thread_id):
    nickname=get_nickname()
    room = Room.query.get(thread_id)
    if current_user not in room.users:
        return "あなたはこの部屋への入室を許可されていません。"
    conversations = Conversation.query.filter_by(room_id=thread_id).all()
    conversations_with_nicknames_selfornot = [(conversation, conversation.user.nickname, conversation.user.id==current_user.id) for conversation in conversations]
    return render_template('thread.html', thread=room, conversations_with_nicknames_selfornot=conversations_with_nicknames_selfornot, nickname=nickname)

#############################################
# socket
def confirm_session():
    if 'nickname' in session:
        nickname=session['nickname']
    else:
        nickname=User.query.get(current_user.id).nickname
        session['nickname'] = nickname
    if 'rooms' not in session:
        session['rooms'] = {}
    return nickname

@socketio.on('join')
def on_join(data):
    room_id = data['room_id']
    join_room(room_id)
    nickname=confirm_session()
    if room_id not in session['rooms'].keys():
        session['rooms'][room_id]=True
    print('SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS')
    try:
        print('qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq')
        emit('join_room', {'room_id': room_id, 'nickname': nickname}, room=room_id)
        print('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    except Exception as e:
        print(f"An error occurred: {e}")
    conversation_post(datetime.now(), '**********'+nickname+"さんが入室しました"+'**********', current_user.id, room_id)
    print('GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG')

@socketio.on('leave')#使ってない
def on_leave(data):
    room_id = data['room_id']
    leave_room(room_id)
    nickname=confirm_session()
    if room_id in session['rooms'].keys():
        del session['rooms'][room_id]
    try:
        emit('leave_room', {'room_id': room_id, 'nickname': nickname}, room=room_id)
    except Exception as e:
        print(f"An error occurred: {e}")
    conversation_post(datetime.now(), '**********'+nickname+"さんが退室しました"+'**********', current_user.id, room_id)

@socketio.on('disconnect')
def on_disconnect():
    nickname=confirm_session()
    for room_id in session['rooms'].keys():
        try:
            emit('leave_room', {'room_id': room_id, 'nickname': nickname}, room=room_id)
        except Exception as e:
            print(f"An error occurred: {e}")
        conversation_post(datetime.now(), '**********'+nickname+"さんが切断しました"+'**********', current_user.id, room_id)
    session['rooms']={}

@socketio.on('send_message')
def handle_send_message(message):
    print('received message: ' + message['content'])
    timestamp=datetime.now()
    content = Markup.escape(message['content']).replace('\n', Markup('<br>'))
    user_id=current_user.id
    room_id=message['room_id']
    conversation=Conversation(timestamp=timestamp, content=content, user_id=user_id, room_id=room_id)
    conversation_data = {
        'timestamp': conversation.timestamp.strftime("%m/%d/%Y, %H:%M:%S"), 
        'content': conversation.content,
        'user_id': conversation.user_id,
        'room_id': conversation.room_id,
        'user_nickname': User.query.get(user_id).nickname,
    }
    try:
        emit('receive_message', conversation_data, room=room_id)
    except Exception as e:
        print(f"An error occurred: {e}")
    db.session.add(conversation)
    db.session.commit()

#############################################
#実行
if __name__ == '__main__':
    time.sleep(18)
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)


