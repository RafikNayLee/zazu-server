from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_marshmallow import Marshmallow 
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
load_dotenv()
from functools import wraps
import os
import feedparser
import jwt
import datetime


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///news-org.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
CORS(app)
db = SQLAlchemy(app)
ma = Marshmallow(app)
SECRET_KEY = os.environ.get("SECRET_KEY")


#RELATIONAL TABLES
categories_feeds = db.Table("categories_feeds", 
    db.Column("feed_id", db.Integer, db.ForeignKey("feeds.id")),
    db.Column("categorie_id", db.Integer, db.ForeignKey("categories.id")),    
)

#MODELS
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    news = db.relationship("NEWS", backref="user")
    feeds = db.relationship("FEED", backref="user")
    categories = db.relationship("CATEGORIE", backref="user")


class NEWS(db.Model):
    __tablename__ = 'news'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    site_url = db.Column(db.String, nullable=False)
    rss_feed_url = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    feeds = db.relationship("FEED", backref="news")
   

class FEED(db.Model):
    __tablename__ = 'feeds'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    link = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    news_id = db.Column(db.Integer, db.ForeignKey("news.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    categories = db.relationship("CATEGORIE", secondary=categories_feeds, backref=db.backref("feeds", lazy="dynamic"))

class CATEGORIE(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))


#SCHEMAS
class NEWSSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'site_url', 'rss_feed_url', 'user_id')
        

class FEEDSchema(ma.SQLAlchemySchema):
    class Meta:
        model = FEED
        include_fk = True
      
    id = ma.auto_field()
    name = ma.auto_field()
    link = ma.auto_field()
    description = ma.auto_field()
    news_id = ma.auto_field()
    user_id = ma.auto_field()
    news = ma.Nested(NEWSSchema)    

class USERSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User
        include_fk = True
      
    id = ma.auto_field()
    email = ma.auto_field()
    news = ma.auto_field()


news_schema = NEWSSchema()
newss_schema = NEWSSchema(many=True)

feed_schema = FEEDSchema()
feeds_schema = FEEDSchema(many=True)

user_schema = USERSchema()
users_schema = USERSchema(many=True)

def decode_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return f(None, *args, **kwargs)

        try: 
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user = User.query.filter_by(id=data['id']).first()
        except:
            return f(None, *args, **kwargs)

        return f(current_user, *args, **kwargs)

    return decorated    

#main route
@app.route("/")
@decode_token
def index(current_user):
    
    if current_user:
        news = NEWS.query.filter_by(user_id=current_user.id).all()
        for n in news:
            NewsFeed = feedparser.parse(n.rss_feed_url)
            for f in NewsFeed.entries:
                exists = FEED.query.filter_by(user_id=current_user.id, news_id=n.id, link=f.link).first()
                if not exists:
                    new_feed = FEED(name=f.title, user_id=current_user.id, news_id=n.id,description=f.description, link=f.link)
                    db.session.add(new_feed)
                    db.session.commit()  
        user_feeds = FEED.query.filter_by(user_id=current_user.id).all()
        return render_template("index.html", feeds=user_feeds)
    else:
        return render_template("index.html", feeds=[])
            
    
    
@app.route("/feeds", methods=["GET"])
@decode_token
def getFeeds(current_user):
    errors = {}
    if not current_user:
        errors["general"] = "You must login first"
        return jsonify({
                "code": 400,
                "errors": errors
            }), 400
       
    else:
        user_feeds = FEED.query.filter_by(user_id=current_user.id).all()
        return feeds_schema.jsonify(user_feeds)

#load_feeds
@app.route("/loadFeeds", methods=["GET"])
@decode_token
def loadFeeds(current_user):
    if not current_user:
        return jsonify({
            "code": 400,
            "message": "You must login first"
        }), 400
    else:
        
        feeds = []
        news = NEWS.query.filter_by(user_id=current_user.id).all()
        for n in news:
            NewsFeed = feedparser.parse(n.rss_feed_url)
            for f in NewsFeed.entries:
                exists = FEED.query.filter_by(user_id=current_user.id, news_id=n.id, link=f.link).first()
                if not exists:
                    new_feed = FEED(name=f.title, user_id=current_user.id, news_id=n.id,description=f.description, link=f.link)
                    db.session.add(new_feed)
                    db.session.commit() 
                    feeds.append(new_feed)
        return feeds_schema.jsonify(feeds) 
        
            
    
    
    

#user routes
@app.route("/login", methods=["POST"])
def login():
    if request.method == "POST":
        errors = {}
        args = request.get_json()
        if not args:
            errors["general"] = "Wrong credentials"
            return jsonify({
                    "code": 400,
                    "errors": errors
                }), 400
        email = args["email"]
        password = args["password"]
       
        if not email:
            errors["email"] = "Email should be provided"
            return jsonify({
                "code": 400,
                "errors": errors
            }), 400
        if not password:
            errors["password"] = "Password should be provided"
            return jsonify({
                "code": 400,
                "errors": errors
            }), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            errors["general"] = "Wrong credentials"
            return jsonify({
                    "code": 400,
                    "errors": errors
                }), 400
        
        if check_password_hash(user.password, password):
            token = jwt.encode({'id' : user.id, 'email': user.email, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, SECRET_KEY, algorithm='HS256')

            return jsonify({'id' : user.id, 'email': user.email,'token': token}), 200
        else:
            errors["general"] = "Wrong credentials"
            return jsonify({
                        "code": 400,
                        "errors": errors
                    }), 400
    else:
        return jsonify({
            "code": 400,
            "message": "This request only accept POST method"
        }), 400


@app.route("/register", methods=["POST"])
def register():
    
    if request.method == "POST":
        errors = {}
        args = request.get_json()
        if not args:
            errors["general"] = "Internal server error"
            return jsonify({
                    "code": 400,
                    "errors": errors
                }), 400
        email = args["email"]
        password = args["password"]
        confirmPassword = args["confirmPassword"]
        
        
        if not email:
            errors["email"] = "Email should be provided"
            return jsonify({
                "code": 400,
                "errors": errors
            }), 400
            
        if not password:
            errors["password"] = "Password should be provided"
            return jsonify({
                "code": 400,
                "errors": errors
            }), 400
            
        if not confirmPassword:
            errors["confirmPassword"] = "Password confirmation should be provided"
            return jsonify({
                "code": 400,
                "errors": errors
            }), 400
            
        if password != confirmPassword:
            errors["confirmPassword"] = "Password and Password confirmation should match"
            return jsonify({
                "code": 400,
                "errors": errors
            }), 400
            
        user = User(email=email, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        token = jwt.encode({'id' : user.id, 'email': email, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, SECRET_KEY, algorithm='HS256')

        return jsonify({'id' : user.id, 'email': email,'token': token}), 200
        
    else:
        return jsonify({
            "code": 400,
            "message": "This request only accept POST method"
        }), 400

#news routes

@app.route("/news/<news_id>", methods=["DELETE"])
@decode_token
def deleteNews(current_user, news_id):
    if not current_user:
        return jsonify({
            "code": 400,
            "message": "You must login first"
        }), 400
    news = NEWS.query.filter_by(user_id=current_user.id, id=news_id).first()
    
    if not news:
        return jsonify({
            "code": 404,
            "message": "News not found"
        }), 404
    feeds = FEED.query.filter_by(user_id=current_user.id, news_id=news_id).delete()
    
    db.session.delete(news)
    db.session.commit()

    return jsonify({
            "code": 200,
            "message": "News item deleted"
        }), 200

@app.route("/news", methods=["GET"])
@decode_token
def getNews(current_user):
    if not current_user:
        return jsonify({
            "code": 400,
            "message": "You must login first"
        }), 400
    
    news = NEWS.query.filter_by(user_id=current_user.id).all()
    return newss_schema.jsonify(news), 200


@app.route("/news", methods=["POST"])
@decode_token
def addNews(current_user):
    if not current_user:
        return jsonify({
            "code": 400,
            "message": "You must login first"
        }), 400
    if request.method == "POST":
        errors = {}
        args = request.get_json()
        if not args:
            errors["general"] = "Wrong credentials"
            return jsonify({
                    "code": 400,
                    "errors": errors
                }), 400
        name = args["name"]
        site_url = args["site_url"]
        rss_feed_url = args["rss_feed_url"]
        
        if not name:
            errors["name"] = "Name should be provided"
            return jsonify({
                "code": 400,
                "errors": errors
            }), 400
            
        if not site_url:
            errors["site_url"] = "Site URL should be provided"
            return jsonify({
                "code": 400,
                "errors": errors
            }), 400
           
        if not rss_feed_url:
            errors["rss_feed_url"] = "RSS Feed URL should be provided"
            return jsonify({
                "code": 400,
                "errors": errors
            }), 400
        news = NEWS(user_id=current_user.id,name=name, site_url=site_url, rss_feed_url=rss_feed_url)
        db.session.add(news)
        db.session.commit()
        
        return news_schema.jsonify(news), 200

    else:
        return jsonify({
            "code": 400,
            "message": "This request only accept POST method"
        }), 400

@app.route("/news/<news_id>", methods=["PUT"])
@decode_token
def updateNews(current_user, news_id):
    if not current_user:
        return jsonify({
            "code": 400,
            "message": "You must login first"
        }), 400
    news = NEWS.query.filter_by(user_id=current_user.id, id=news_id).first()

    if not news:
        return jsonify({
            "code": 404,
            "message": "News not found"
        }), 404

    name = request.form.get("name")
    site_url = request.form.get("site_url")
    rss_feed_url = request.form.get("rss_feed_url")
    if name:
        news.name = name
    if site_url:
        news.site_url = site_url
    if rss_feed_url:
        news.rss_feed_url = rss_feed_url

    db.session.commit()
    return jsonify({
            "code": 200,
            "message": "News item updated successfully"
        }), 200

if __name__ == "__main__":
    app.debug = True
    app.run()