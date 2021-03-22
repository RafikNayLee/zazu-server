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
from time import mktime
from randomColor import getRandomColor


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
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
    color = db.Column(db.String, default=getRandomColor())
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    feeds = db.relationship("FEED", backref="news")
   

class FEED(db.Model):
    __tablename__ = 'feeds'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    link = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    pubDate = db.Column(db.DateTime, nullable=False)
    read = db.Column(db.Boolean, default=False, nullable=False)
    news_id = db.Column(db.Integer, db.ForeignKey("news.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    categories = db.relationship("CATEGORIE", secondary=categories_feeds, backref=db.backref("feeds", lazy="dynamic"))

class CATEGORIE(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    color = db.Column(db.String, default=getRandomColor())
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))


#SCHEMAS
class NEWSSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'site_url', 'rss_feed_url', 'user_id', 'color')

class CATEGORIESchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'user_id', 'color')
        

class FEEDSchema(ma.SQLAlchemySchema):
    class Meta:
        model = FEED
        include_fk = True
      
    id = ma.auto_field()
    name = ma.auto_field()
    link = ma.auto_field()
    description = ma.auto_field()
    pubDate = ma.auto_field()
    read = ma.auto_field()
    news_id = ma.auto_field()
    user_id = ma.auto_field()
    news = ma.Nested(NEWSSchema) 
    categories = ma.Nested(CATEGORIESchema(many=True))   

class USERSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User
        include_fk = True
      
    id = ma.auto_field()
    email = ma.auto_field()
    news = ma.auto_field()


news_schema = NEWSSchema()
newss_schema = NEWSSchema(many=True)

categorie_schema = CATEGORIESchema()
categories_schema = CATEGORIESchema(many=True)

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


def getUnAuthError():
    errors = {}
    errors["general"] = "Your session has expired, please login to your account to continue."
    return jsonify({
            "code": 401,
            "errors": errors
        }), 401


    
#feeds routes
@app.route("/feeds/read/<feed_id>", methods=["POST"])
@decode_token
def readFeed(current_user, feed_id):
    if not current_user:
        return getUnAuthError()
    
    errors = {}
    
    if not feed_id:
        errors["general"] = "Feed id must be provided"
        return jsonify({
                "code": 400,
                "errors": errors
            }), 400

    feed = FEED.query.filter_by(user_id=current_user.id, id=feed_id).first()
    if feed.read:
        feed.read = False
    else:
        feed.read = True
    db.session.commit()
    return feed_schema.jsonify(feed)
            

@app.route("/feeds", methods=["GET"])
@decode_token
def getFeeds(current_user):
    
    if not current_user:
        return getUnAuthError()
       
    else:
        user_feeds = FEED.query.filter_by(user_id=current_user.id).all()
          
        return feeds_schema.jsonify(user_feeds)

#load_feeds
@app.route("/loadFeeds", methods=["GET"])
@decode_token
def loadFeeds(current_user):
    if not current_user:
        return getUnAuthError()
    
        
    feeds = []
    news = NEWS.query.filter_by(user_id=current_user.id).all()
    for n in news:
        NewsFeed = feedparser.parse(n.rss_feed_url)
        
        for f in NewsFeed.entries:
            
            exists = FEED.query.filter_by(user_id=current_user.id, news_id=n.id, link=f.link).first()
            if not exists:
                new_feed = FEED(name=f.title, user_id=current_user.id, news_id=n.id,description=f.description, link=f.link, pubDate=datetime.datetime.fromtimestamp(mktime(f.published_parsed)))
                db.session.add(new_feed)
                db.session.commit() 
                feeds.append(new_feed)
    return feeds_schema.jsonify(feeds) 
        
@app.route("/feeds/<feed_id>/categories", methods=["PUT"])
@decode_token
def setFeedCategories(current_user, feed_id):
    if not current_user:
        return getUnAuthError()

    errors = {}
    args = request.get_json()
    if not args:
        errors["general"] = "Args must be provided"
        return jsonify({
                "code": 400,
                "errors": errors
            }), 400
    categories = args["categories"]
    # print(args)
    

    feed = FEED.query.filter_by(user_id=current_user.id, id=feed_id).first()
    if not categories:
        feed.categories = []
    else:
        found_categories = [] 
        for c in categories:
            categorie = CATEGORIE.query.filter_by(user_id=current_user.id, id=c).first()
            found_categories.append(categorie)
            feed.categories = found_categories

    db.session.commit()

    return feed_schema.jsonify(feed)
    
    
    
    

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


#categories routes

@app.route("/categories/<categorie_id>", methods=["DELETE"])
@decode_token
def deleteCategorie(current_user, categorie_id):
    if not current_user:
        return getUnAuthError()
    categorie = CATEGORIE.query.filter_by(user_id=current_user.id, id=categorie_id).first()
    errors = {}
    if not categorie:
        errors["general"] = "Categorie not found"
        return jsonify({
            "code": 404,
            "errors": errors
        }), 404
    feeds = FEED.query.filter_by(user_id=current_user.id).all()
    for f in feeds:
        for cat in f.categories:
            if cat.id == categorie_id:
                errors["general"] = "Categorie is used in feeds"
                return jsonify({
                    "code": 400,
                    "errors": errors
                }), 400

    
    
    db.session.delete(categorie)
    db.session.commit()

    return jsonify({
            "code": 200,
            "message": "News item deleted"
        }), 200

@app.route("/categories", methods=["GET"])
@decode_token
def getCategories(current_user):
    if not current_user:
        return getUnAuthError()
    
    categories = CATEGORIE.query.filter_by(user_id=current_user.id).all()
    return categories_schema.jsonify(categories), 200


@app.route("/categories", methods=["POST"])
@decode_token
def addCategorie(current_user):
    if not current_user:
        return getUnAuthError()
    if request.method == "POST":
        errors = {}
        args = request.get_json()
        if not args:
            errors["general"] = "Args must be provided"
            return jsonify({
                    "code": 400,
                    "errors": errors
                }), 400
        name = args["name"]
       
        
        if not name:
            errors["name"] = "Name should be provided"
            return jsonify({
                "code": 400,
                "errors": errors
            }), 400
            
        
        categorie = CATEGORIE(user_id=current_user.id, name=name, color=getRandomColor())
        db.session.add(categorie)
        db.session.commit()
        
        return categorie_schema.jsonify(categorie), 200

    else:
        return jsonify({
            "code": 400,
            "message": "This request only accept POST method"
        }), 400

@app.route("/categories/<categorie_id>", methods=["PUT"])
@decode_token
def updateCategorie(current_user, categorie_id):
    if not current_user:
        return getUnAuthError()
    categorie = CATEGORIE.query.filter_by(user_id=current_user.id, id=categorie_id).first()
    errors = {}
    if not categorie:
        errors["general"] = "Categorie not found"
        return jsonify({
            "code": 404,
            "errors": errors
        }), 404
    
    
    args = request.get_json()
    if not args:
        errors["general"] = "Args must be provided"
        return jsonify({
                "code": 400,
                "errors": errors
            }), 400
    name = args["name"]
   
    if name:
        categorie.name = name
   

    db.session.commit()
    return categorie_schema.jsonify(categorie)


#news routes

@app.route("/news/<news_id>", methods=["DELETE"])
@decode_token
def deleteNews(current_user, news_id):
    if not current_user:
        return getUnAuthError()
    news = NEWS.query.filter_by(user_id=current_user.id, id=news_id).first()
    errors = {}
    if not news:
        errors["general"] = "News not found"
        return jsonify({
            "code": 404,
            "errors": errors
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
        return getUnAuthError()
    
    news = NEWS.query.filter_by(user_id=current_user.id).all()
    return newss_schema.jsonify(news), 200


@app.route("/news", methods=["POST"])
@decode_token
def addNews(current_user):
    if not current_user:
        return getUnAuthError()
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
        news = NEWS(user_id=current_user.id,name=name, site_url=site_url, rss_feed_url=rss_feed_url, color=getRandomColor())
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
        return getUnAuthError()
    news = NEWS.query.filter_by(user_id=current_user.id, id=news_id).first()
    errors = {}
    if not news:
        errors["general"] = "News not found"
        return jsonify({
            "code": 404,
            "errors": errors
        }), 404


    args = request.get_json()
    if not args:
        errors["general"] = "Args must be provided"
        return jsonify({
                "code": 400,
                "errors": errors
            }), 400
    name = args["name"]
    site_url = args["site_url"]
    rss_feed_url = args["rss_feed_url"]
    
    if name:
        news.name = name
    if site_url:
        news.site_url = site_url
    if rss_feed_url:
        news.rss_feed_url = rss_feed_url

    db.session.commit()
    return news_schema.jsonify(news)


def runApp():
    app.run()
    return app

if __name__ == "__main__":
    runApp()