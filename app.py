import pickle
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from newsapi import NewsApiClient
from werkzeug.security import generate_password_hash, check_password_hash
from forms import LoginForm, RegisterForm, UploadNewsForm
#import hashlib




app = Flask(
    __name__)  # create instance of flaskwebapplication using flask constructor __name__ tells name of application to locate other files and templates

# def cm():
#     Confuse_matrix = confusion_matrix(labels_test, model_predictions)
#     return Confuse_matrix

import os
print(os.getcwd())
import pickle

tfid, cm, Input = pickle.load(open('C:/finalproject/Overall.pkl', 'rb'))
  # loads feature extraction model from binary file i.e,feature.pkl
model = pickle.load(open('model.pkl', 'rb'))

app.config[
    'SECRET_KEY'] = 'Thhisissecretkey'  # sets 'secret key' config to flask  instance i.e, app to 'Thhisissecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/finalproject/database.db'  # Configure db connection
bootstrap = Bootstrap(app)  # initialize bootstrap extension to app
db = SQLAlchemy(app)  # initialize SQLAlchemy extension to app
login_manager = LoginManager()  # initialize login manage() for authentication,authorization and user session
login_manager.init_app(app)  # Registers login manager extension with app
login_manager.login_view = 'login'  # sets login_manager.login_view to log in


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


class News(db.Model):
    title = db.Column(db.String(250), primary_key=True)
    desc = db.Column(db.String(600))
    img = db.Column(db.String(200))
    content = db.Column(db.String(1500))
    url = db.Column(db.String(200))
    ctr = db.Column(db.String(20))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# noinspection PyUnusedLocal
def GetNewsOnline(source, ctr):  # defining function
    newsapi = NewsApiClient(
        api_key="38122ac1faf54ee2acdbc704e062cd89")  # assigning newsapi with news api client(api key)->api key is req authenticate and access newsapi service
    topheadlines = newsapi.get_top_headlines()  # access news with top headlines

    articles = topheadlines['articles']  # assigning articles with headlines

    desc = []  # assigning list
    news = []
    img = []
    url = []

    for i in range(len(articles)):
        myarticles = articles[i]
        news.append(myarticles['title'])
        desc.append(myarticles['description'])
        img.append(myarticles['urlToImage'])
        url.append(myarticles['url'])

        news_title = News.query.filter_by(title=myarticles[
            'title']).first()  # Querying 'News' table and retrieving title with first row that matches
        if news_title:
            # noinspection PyStatementEffect
            None  # Checks if news_title is specified
        else:  # if title not specified
            new_news = News(title=myarticles['title'], desc=myarticles['description'], img=myarticles['urlToImage'],
                            content=myarticles['content'], url=myarticles['url'], ctr=ctr)
            # specifying news details
            db.session.add(new_news)  # add new news to db
            db.session.commit()  # save changes into db

    myList = zip(news, desc, img, url)  # Zips 4 list into list of tuples repr news,desc,img,url
    return myList  # returns list of tuples


# noinspection PyUnusedLocal
def GetNews(source, ctr=None):  # defining function GetNews with source and category none

    db_news = News.query.all()  # Query 'News' table and retrieve all

    desc = []  # Assigning desc to list
    news = []
    img = []
    url = []

    if ctr:  # checks if category is specified
        for n in reversed(db_news):  # from newest to oldest news from database
            if n.ctr == ctr:  # Checks if current news articles belongs to specified news or not
                news.append(n.title)  # if belongs to category then append title,desc,image and url
                desc.append(n.desc)
                img.append(n.img)
                url.append(n.url)
    else:  # if category not specified
        for n in reversed(db_news):  # from newest to oldest
            news.append(n.title)  # append title,desc,img and url
            desc.append(n.desc)
            img.append(n.img)
            url.append(n.url)

    myList = zip(news, desc, img, url)  # Zips 4 list into list of tuples repr news,desc,img,url
    return myList  # returns list of tuples


@app.route('/')  # Register view function
def index():  # View function that process incoming req,perform and response

    # new_news = News(id=22,title="RAM")
    # db.session.add(new_news)
    # db.session.commit()

    return render_template('index.html')  # Renders index.html template


@app.route('/login', methods=['GET', 'POST'])  # Register view function with either GET or POST method
def login():  # View function that process incoming req,perform and repose
    form = LoginForm()  # LoginForm instance creation and assigns to form

   
    if form.validate_on_submit():
        user = User.query.filter_by(
            username=form.username.data).first()  # Query 'User' table in db and checks username into db and retrieve first row else none
        if user:  # Checks if user exists or not and user will be set to corresponding 'User' object
            if check_password_hash(user.password, form.password.data):  # Check if hashed password is matched or not
                login_user(user,
                           remember=form.remember.data)  # Log in user with user object and remember which will save if browser is closed too
                return redirect(url_for('dashboard'))  # Redirects to dashboard view function

        return '<h1> Invalid username or password </h1>'

    return render_template('login.html', form=form)  # Renders login.html with passing form=Loginform()


@app.route('/signup', methods=['GET', 'POST'])  # Register view function with either GET or POST method
def signup():  # View function that process incoming req,perform and repose
    form = RegisterForm()  # RegisterForm instance creation and assigns to form

    if form.validate_on_submit():  # Check form validation from RegisterForm defined in forms.py
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')  # Password hashed with SHA256
        #hashed_password = hashlib.md5(form.password.data.encode()).hexdigest()
        # noinspection PyArgumentList
        new_user = User(username=form.username.data, email=form.email.data,
                        password=hashed_password)  # new_user instance with User info
        db.session.add(new_user)  # Add new_user to database
        db.session.commit()  # Save changes to database

        return redirect(url_for('login'))  # Redirects to login page with login view function after successful operation

    return render_template('signup.html',
                           form=form)  # Renders signup.html and passing form to signup.html help to render correct field and validate which is defined in forms.py


@app.route('/dashboard', methods=['GET', 'POST'])  # Registers view function and response with either GET OR POST method
@login_required  # Access to logged-in user otherwise redirect to login page
def dashboard():  # defining view function that process,performs and response

    dash = GetNews(source=dbnews)  # GetNews class is responsible for retrieving news article form news API or source,
    # here source is None so retrieve form newsAPI and ctr is for category,here it is Technology category
    return render_template('dashboard.html', name=current_user.username,
                           context=dash)  # Renders dashboard.html with current username and


@app.route('/logout')  # Registers view function
@login_required  # Access restriction to logged-in  user and if not they are redirected to log in form
def logout():  # defining view function
    logout_user()  # End session of current user
    return redirect(url_for('index'))  # Redirects to index view function


# noinspection PyShadowingNames
@app.route('/business', methods=['GET'])  # Registers view function
@login_required  # Access restriction to logged-in  user and if not they are redirected to log in form
def business():  # defining view function

    business = GetNews(source=dbnews,
                       ctr="business")  # GetNews class is responsible for retrieving news article form news API or source,
    # here source is None so retrieve form newsAPI and ctr is for category,here it is Business category

    return render_template('business.html', name=current_user.username,
                           context=business)  # Renders business.html template with current username and category


# noinspection PyShadowingNames
@app.route('/entertainment')  # Registers view function
@login_required  # Access restriction to logged-in  user and if not they are redirected to log in form
def entertainment():  # defining view function

    entertainment = GetNews(source=dbnews, ctr="entertainment")

    return render_template('entertainment.html', name=current_user.username, context=entertainment)


# noinspection PyShadowingNames
@app.route('/politics')  # Registers view function
@login_required  # Access restriction to logged-in  user and if not they are redirected to log in form
def politics():  # defining view function

    politics = GetNews(source=dbnews, ctr="politics")

    return render_template('politics.html', name=current_user.username, context=politics)


# noinspection PyShadowingNames
@app.route('/sports')  # Registers view function
@login_required  # Access restriction to logged-in  user and if not they are redirected to log in form
def sports():  # defining view function

    sports = GetNews(source=dbnews, ctr="sports")

    return render_template('sports.html', name=current_user.username, context=sports)


# noinspection PyShadowingNames
@app.route('/technology')  # Registers view function
@login_required  # Access restriction to logged-in  user and if not they are redirected to log in form
def technology():  # defining view function

    technology = GetNews(source=dbnews, ctr="technology")

    return render_template('technology.html', name=current_user.username, context=technology)


# noinspection PyStatementEffect
@app.route('/upload', methods=['GET', 'POST'])  # Registers view function
@login_required  # Access restriction to logged-in  user and if not they are redirected to log in form
def upload():  # defining view function
    form = UploadNewsForm()  # Assigning UploadNewsForm class in form
    category = form.category.data
    if form.validate_on_submit():  # Checking for form validation on submit
        if category == 'predict':
            input = form.desc.data
            input = [input]
            newnews = tfid.transform(input).toarray()
            prediction = model.predict(newnews)
            print(prediction)
            if prediction == [0]:
                context = 'business'
            elif prediction == [1]:
                context = 'entertainment'
            elif prediction == [2]:
                context = 'politics'
            elif prediction == [3]:
                context = 'sports'
            else:
                context = 'technology'
        else:
            if category == 'business':
                context = 'business'
            elif category == 'politics':
                context = 'politics'
            elif category == 'tech':
                context = 'technology'
            elif category == 'sport':
                context = 'sports'
            else:
                context = 'entertainment'

        news_title = News.query.filter_by(
            title=form.title.data).first()  # Querying the 'News' table in database and retrieving title whose matches form title and first() retrieve first row that matches filter if none the 'None' is returned
        # noinspection PyStatementEffect
        if news_title:
            None
        else:
            new_news = News(title=form.title.data, desc=form.desc.data, img=None, content=None,
                            url=None, ctr=context)
            db.session.add(new_news)  # Add new_news to the db
            db.session.commit()  # Saves changes to db

        return redirect(url_for('processing', title=form.title.data, desc=form.desc.data, category=form.category.data))

    return render_template('upload.html', form=form)


@app.template_filter('round')
def _round(value):
    return round(value, 2)


@app.route('/processing/<title>/<desc>/<category>', methods=['GET', 'POST'])  # Registers view function
@login_required  # Access privilege for logged in user else redirect to login page
def processing(title, desc, category):  # defining view function with title and desc as parameter for processing
    if category == 'predict':
        input = [desc]  # assigns input text with list of strings
        new_news = tfid.transform(input).toarray()  # transform(input) changes input into matrix of numeric features
        # and toarray changes matrix into numpy array
        prediction = model.predict(new_news)  # Predicts new_news with pre-trained model which is trained in model.py
        print(prediction)
        CM = cm()
        if prediction == [0]:
            context = 'Business'

            cm0 = (CM[0, 0] / (CM[0, 0] + CM[0, 1] + CM[0, 2] + CM[0, 3] + CM[0, 4])) * 100
            cm1 = (CM[0, 1] / (CM[0, 1] + CM[0, 2] + CM[0, 3] + CM[0, 4] + CM[0, 0])) * 100
            cm2 = (CM[0, 2] / (CM[0, 2] + CM[0, 0] + CM[0, 1] + CM[0, 3] + CM[0, 4])) * 100
            cm3 = (CM[0, 3] / (CM[0, 3] + CM[0, 1] + CM[0, 2] + CM[0, 0] + CM[0, 4])) * 100
            cm4 = (CM[0, 4] / (CM[0, 4] + CM[0, 1] + CM[0, 2] + CM[0, 3] + CM[0, 0])) * 100

        elif prediction == [1]:
            context = 'Entertainment'

            cm0 = (CM[1, 0] / (CM[1, 0] + CM[1, 1] + CM[1, 2] + CM[1, 3] + CM[1, 4])) * 100
            cm1 = (CM[1, 1] / (CM[1, 1] + CM[1, 0] + CM[1, 2] + CM[1, 3] + CM[1, 4])) * 100
            cm2 = (CM[1, 2] / (CM[1, 2] + CM[1, 1] + CM[1, 0] + CM[1, 3] + CM[1, 4])) * 100
            cm3 = (CM[1, 3] / (CM[1, 3] + CM[1, 1] + CM[1, 2] + CM[1, 0] + CM[1, 4])) * 100
            cm4 = (CM[1, 4] / (CM[1, 4] + CM[1, 1] + CM[1, 2] + CM[1, 3] + CM[1, 0])) * 100

        elif prediction == [2]:
            context = 'Politics'

            cm0 = (CM[2, 0] / (CM[2, 0] + CM[2, 1] + CM[2, 2] + CM[2, 3] + CM[2, 4])) * 100
            cm1 = (CM[2, 1] / (CM[2, 1] + CM[2, 1] + CM[2, 2] + CM[2, 3] + CM[2, 4])) * 100
            cm2 = (CM[2, 2] / (CM[2, 2] + CM[2, 1] + CM[2, 2] + CM[2, 3] + CM[2, 4])) * 100
            cm3 = (CM[2, 3] / (CM[2, 3] + CM[2, 1] + CM[2, 2] + CM[2, 3] + CM[2, 4])) * 100
            cm4 = (CM[2, 4] / (CM[2, 4] + CM[2, 1] + CM[2, 2] + CM[2, 3] + CM[2, 4])) * 100

        elif prediction == [3]:
            context = 'Sports '

            cm0 = (CM[3, 0] / (CM[3, 0] + CM[3, 1] + CM[3, 2] + CM[3, 3] + CM[3, 4])) * 100
            cm1 = (CM[3, 1] / (CM[3, 1] + CM[3, 0] + CM[3, 2] + CM[3, 3] + CM[3, 4])) * 100
            cm2 = (CM[3, 2] / (CM[3, 2] + CM[3, 1] + CM[3, 0] + CM[3, 3] + CM[3, 4])) * 100
            cm3 = (CM[3, 3] / (CM[3, 3] + CM[3, 1] + CM[3, 2] + CM[3, 0] + CM[3, 4])) * 100
            cm4 = (CM[3, 4] / (CM[3, 4] + CM[3, 1] + CM[3, 2] + CM[3, 3] + CM[3, 0])) * 100

        else:
            context = 'Technology'

            cm0 = (CM[4, 0] / (CM[4, 0] + CM[4, 1] + CM[4, 2] + CM[4, 3] + CM[4, 4])) * 100
            cm1 = (CM[4, 1] / (CM[4, 1] + CM[4, 0] + CM[4, 2] + CM[4, 3] + CM[4, 4])) * 100
            cm2 = (CM[4, 2] / (CM[4, 2] + CM[4, 1] + CM[4, 0] + CM[4, 3] + CM[4, 4])) * 100
            cm3 = (CM[4, 3] / (CM[4, 3] + CM[4, 1] + CM[4, 2] + CM[4, 0] + CM[4, 4])) * 100
            cm4 = (CM[4, 4] / (CM[4, 4] + CM[4, 1] + CM[4, 2] + CM[4, 3] + CM[4, 0])) * 100
        return render_template('processing.html', t=title, d=desc, context=context, cm0=cm0, cm1=cm1, cm2=cm2,
                               cm3=cm3,
                               cm4=cm4)
    else:
        input = [desc]
        Input(input, category)
        return render_template('processing.html', t=title, d=desc, context=category, cm0=0, cm1=0, cm2=0, cm3=0,
                               cm4=0)


# noinspection PyShadowingNames
@app.route('/dbnews', methods=['GET', 'POST'])  # Register view function
@login_required  # Access privilege for logged-in user if not redirect to login page
def dbnews():  # defining view function

    business = GetNewsOnline(source=None, ctr='business')
    print("done")
    entertainment = GetNewsOnline(source=None, ctr='entertainment')
    print("done")
    politics = GetNewsOnline(source=None, ctr='politics')
    print("done")
    sports = GetNewsOnline(source=None, ctr='sport')
    print("done")
    technology = GetNewsOnline(source=None, ctr='technology')
    print("done")

    return render_template('dbnews.html', name=current_user.username,
                           context=[politics, business, sports, technology, entertainment])


# noinspection PyShadowingNames
@app.route('/guest')  # Register view function
def guest():  # defining view function

    guest = GetNews(source=dbnews)  # Getting news from newsApi as source is None and category is none too

    return render_template('guest.html', context=guest)  # Renders guest.html and passed guest from above


if __name__ == '__main__':  # Checks whether current module is run as main module
    app.run(debug=True)  # Responsible for running the app in debug mode
