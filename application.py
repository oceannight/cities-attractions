#!/usr/bin/env python

from flask import Flask, render_template, request, redirect, jsonify
from flask import flash, url_for
from functools import wraps
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, City, Attraction, User
from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Cities and Attractions"

# Connect to Database and create database session
engine = create_engine('postgresql://catalog:catalog@localhost/catalog',
                       connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# check for login

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            return f(*args, **kwargs)
        else:
            return redirect('/login')
    return decorated_function


# create google login

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code
    code = request.data
    print code

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # Check if there was an error in the access token info.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
                                 'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = newUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style="width:100px;height:100px;border-radius:150px;"> '
    return output


# disconnect user

@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response


# Get User info

def newUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUser(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception:
        return None


# get Json endpoint

@app.route('/city/<int:city_id>/attraction/JSON')
def cityJSON(city_id):
    city = session.query(City).filter_by(id=city_id).one()
    attractions = session.query(Attraction).filter_by(city_id=city_id).all()
    return jsonify(attractions=[i.serialize for i in attractions])


@app.route('/city/<int:city_id>/attraction/<int:attraction_id>/JSON')
def AttractionJSON(city_id, attraction_id):
    attraction = session.query(Attraction).filter_by(id=attraction_id).one()
    return jsonify(attraction=attraction.serialize)


@app.route('/city/JSON')
def allcityJSON():
    cities = session.query(City).all()
    return jsonify(cities=[r.serialize for r in cities])


# home page that lists all cities and latest attractions
@app.route('/')
@app.route('/index/')
def showAll():
    cities = session.query(City).order_by(asc(City.name))
    attractions = session.query(Attraction).order_by(
                  desc(Attraction.date)).limit(8).all()
    isLogin = False
    print login_session
    if 'username' in login_session:
        isLogin = True
    return render_template('index.html', cities=cities,
                           attractions=attractions, isLogin=isLogin)


# show a city and its attractions
@app.route('/city/<int:city_id>/')
def showCity(city_id):
    cities = session.query(City).order_by(asc(City.name))
    city = session.query(City).filter_by(id=city_id).one()
    attractions = session.query(Attraction).filter_by(city_id=city_id).all()
    owner = getUser(city.user_id)
    isLogin = False
    if 'username' in login_session:
        isLogin = True
    if 'username' not in login_session or owner.id != login_session['user_id']:
        return render_template('publicCity.html', city=city, cities=cities,
                               attractions=attractions, isLogin=isLogin,
                               owner=owner)
    return render_template('city.html', city=city, cities=cities,
                           attractions=attractions, isLogin=isLogin)


# create a new city
@app.route('/city/new/', methods=['GET', 'POST'])
@login_required
def newCity():
    if request.method == 'POST':
        newCity = City(name=request.form['name'],
                       user_id=login_session['user_id'])
        session.add(newCity)
        session.commit()
        flash("City %s is successfully created" % (newCity.name))
        return redirect(url_for('showCity', city_id=newCity.id))
    else:
        return render_template('newCity.html')


# edit a city
@app.route('/city/<int:city_id>/edit/', methods=['GET', 'POST'])
@login_required
def editCity(city_id):
    editedCity = session.query(City).filter_by(id=city_id).one()
    owner = getUser(editedCity.user_id)
    if owner.id != login_session['user_id']:
        flash("You are not allowed to make change")
        return redirect(url_for('showCity', city_id=editedCity.id))
    elif request.method == 'POST':
        if request.form['name']:
            editedCity.name = request.form['name']
            session.add(editedCity)
            session.commit()
            flash('City %s is successfully edited' % (editedCity.name))
            return redirect(url_for('showCity', city_id=editedCity.id))
    else:
        return render_template('editCity.html', city=editedCity)


# delete a city
@app.route('/city/<int:city_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteCity(city_id):
    cityToDelete = session.query(City).filter_by(id=city_id).one()
    owner = getUser(cityToDelete.user_id)
    if owner.id != login_session['user_id']:
        flash("You are not allowed to delete")
        return redirect(url_for('showCity', city_id=cityToDelete.id))
    elif request.method == 'POST':
        session.delete(cityToDelete)
        session.commit()
        flash('City %s has been deleted' % (cityToDelete.name))
        return redirect(url_for('showAll'))
    else:
        return render_template('deleteCity.html', city=cityToDelete)


# show info on an attraction
@app.route('/city/<int:city_id>/attraction/<int:attraction_id>/')
def showAttraction(city_id, attraction_id):
    attraction = session.query(Attraction).filter_by(id=attraction_id).one()
    city = session.query(City).filter_by(id=city_id).one()
    owner = getUser(city.user_id)
    isLogin = False
    if 'username' in login_session:
        isLogin = True
    if 'username' not in login_session or owner.id != login_session['user_id']:
        return render_template('publicAttraction.html', city=city,
                               attraction=attraction, isLogin=isLogin,
                               owner=owner)
    else:
        return render_template('attraction.html', city=city,
                               attraction=attraction, isLogin=isLogin)


# creat a new attraction
@app.route('/city/<int:city_id>/attraction/new/', methods=['GET', 'POST'])
@login_required
def newAttraction(city_id):
    city = session.query(City).filter_by(id=city_id).one()
    if request.method == 'POST':
        newAttraction = Attraction(name=request.form['name'],
                                   description=request.form['description'],
                                   city_id=city_id, user_id=city.user_id)
        session.add(newAttraction)
        session.commit()
        flash("Attraction %s has been successfully created"
              % (newAttraction.name))
        return redirect(url_for('showAttraction', city_id=city.id,
                        attraction_id=newAttraction.id))
    else:
        return render_template('newAttraction.html', city_id=city_id)


# edit an attraction
@app.route('/city/<int:city_id>/attraction/<int:attraction_id>/edit/',
           methods=['GET', 'POST'])
@login_required
def editAttraction(city_id, attraction_id):
    city = session.query(City).filter_by(id=city_id).one()
    editedAttraction = session.query(Attraction).filter_by(
                       id=attraction_id).one()
    owner = getUser(city.user_id)
    if owner.id != login_session['user_id']:
        flash("You are not allowed to make change")
        return redirect(url_for('showAttraction', city_id=city.id,
                        attraction_id=editedAttraction.id))
    elif request.method == 'POST':
        if request.form['name']:
            editedAttraction.name = request.form['name']
        if request.form['description']:
            editedAttraction.description = request.form['description']
        session.add(editedAttraction)
        session.commit()
        flash("Attraction %s has been successfully edited" %
              (editedAttraction.name))
        return redirect(url_for('showAttraction', city_id=city_id,
                                attraction_id=attraction_id))
    else:
        return render_template('editAttraction.html',
                               city=city, attraction=editedAttraction)


# delete an attraction
@app.route('/city/<int:city_id>/attraction/<int:attraction_id>/delete/',
           methods=['GET', 'POST'])
@login_required
def deleteAttraction(city_id, attraction_id):
    attractionToDelete = session.query(Attraction).filter_by(
                         id=attraction_id).one()
    city = session.query(City).filter_by(id=city_id).one()
    owner = getUser(city.user_id)
    if owner.id != login_session['user_id']:
        flash("You are not allowed to delete")
        return redirect(url_for('showAttraction', city_id=city.id,
                        attraction_id=attractionToDelete.id))
    if request.method == 'POST':
        session.delete(attractionToDelete)
        session.commit()
        flash("Attraction %s has been successfully deleted" %
              (attractionToDelete.name))
        return redirect(url_for('showCity', city_id=city_id))
    else:
        return render_template('deleteAttraction.html',
                               city=city, attraction=attractionToDelete)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(port="80")
