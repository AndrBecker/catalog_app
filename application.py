from flask import Flask, render_template, request, url_for, redirect
from flask import flash, jsonify, session as login_session
from datetime import datetime
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from database_setup import Base, Category, Item, Role, User
import random
import string
import hashlib

# imports for oauth-handling
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


#  LOGGING  ----------------

import logging
logger = logging.getLogger('logger')
hdlr = logging.FileHandler('application.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

# ---------------------------


app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "CategoryItemServer"


engine = create_engine('sqlite:///category_item.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

# -----------------------------


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
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

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('User is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    if stored_credentials is not None:
        del login_session['credentials']

    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    if 'name' in data:
        login_session['username'] = data['name']
    if 'picture' in data:
        login_session['picture'] = data['picture']
    if 'email' in data:
        login_session['email'] = data['email']
    if 'given_name' in data:
        login_session['given_name'] = data['given_name']
    if 'family_name' in data:
        login_session['family_name'] = data['family_name']

    # Find user among registered users

    try:
        user = session.query(User).filter_by(gplus_id=str(gplus_id)).one()

        # user found (no exception)

        login_session['logged_in'] = True
        login_session['user_id'] = str(user.id)

        if user.role.name == "admin":
            login_session['admin_user'] = True
            flash("you logged in sucessfully as admin")
        else:
            flash("you logged in sucessfully")

    except NoResultFound, e:

        # user unknown, user is created

        loginEmail = login_session.get('email')
        if loginEmail is None:
            loginEmail = ''

        roleStandard = session.query(Role).filter_by(name="standard").one()
        newUser = User(
            name=login_session['username'],
            gplus_id=str(login_session['gplus_id']),
            email=loginEmail,
            role=roleStandard,
            created_at=datetime.now())
        session.add(newUser)
        session.commit()
        login_session['logged_in'] = True
        login_session['user_id'] = str(newUser.id)
        flash("you were registered as new user and are logged in")

    flash("you are now logged in as %s" % login_session['username'])
    response = make_response(json.dumps('Successfully connected.'), 200)
    response.headers['Content-Type'] = 'application/json'
    return response


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('credentials')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['picture']
        if 'email' in login_session:
            del login_session['email']
        if 'given_name' in login_session:
            del login_session['given_name']
        if 'family_name' in login_session:
            del login_session['family_name']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


def isLoggedIn():
    if 'logged_in' in login_session and 'user_id' in login_session:
        return True
    return False


def isLoggedInAdmin():
    if isLoggedIn() and 'admin_user' in login_session:
        return True
    return False


def isLoggedInOwner(id):
    if isLoggedIn() and login_session['user_id'] == str(id):
        return True
    return False


# LIST CATEGORY

@app.route('/')
@app.route('/category/')
def listCategory():
    categories = session.query(Category).all()
    items = session.query(Item).order_by(desc(Item.id)).limit(15)
    if 'logged_in' in login_session:
        return render_template('listcategoryloggedin.html',
                               categories=categories, items=items,
                               itemHeading="Latest Items",
                               isLoggedIn=isLoggedIn(),
                               isAdmin=isLoggedInAdmin())
    else:
        return render_template('listcategory.html',
                               categories=categories, items=items,
                               itemHeading="Latest Items",
                               isLoggedIn=isLoggedIn(),
                               isAdmin=False)


# NEW CATEGORY

@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    if not isLoggedInAdmin():
        msg = "you are not logged in as admin user and "
        msg += "do not have the right to create a new category"
        flash(msg)
        return redirect(url_for('listCategory'))
    else:
        # POST
        if request.method == 'POST':
            if request.form['name'] and request.form['description']:
                if isLoggedInAdmin():
                    newCategory = Category(
                        name=request.form['name'],
                        description=request.form['description'],
                        creator_id=login_session['user_id'],
                        created_at=datetime.now())
                    session.add(newCategory)
                    session.commit()
                    flash("new category created")
                else:
                    msg = "you are not logged in or "
                    msg += "do not have the right to create a new category"
                    flash(msg)
            else:
                flash('name or description of new category missing')
            return redirect(url_for('listCategory'))
        else:
            # GET
            return render_template('newcategory.html', isLoggedIn=isLoggedIn())


# CATEGORY EDIT

@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    if not isLoggedInAdmin():
        msg = "you are not logged in as admin user and "
        msg += "do not have the right to edit a category"
        flash(msg)
        return redirect(url_for('listCategory'))

    category = session.query(Category).filter_by(id=category_id).one()

    if request.method == 'POST':
        if (request.form['name']):
            category.name = request.form['name']
        if (request.form['description']):
            category.description = request.form['description']
        session.add(category)
        session.commit()
        flash("category modified")
        return redirect(url_for('listCategory'))
    else:
        return render_template('editcategory.html',
                               category=category, isLoggedIn=isLoggedIn())


# CATEGORY DELETE

@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    if not isLoggedInAdmin():
        msg = "you are not logged in as admin user and "
        msg += "do not have the right to delete a category"
        flash(msg)
        return redirect(url_for('listCategory'))

    category = session.query(Category).filter_by(id=category_id).one()

    if request.method == 'POST':
        items = session.query(Item).filter_by(category_id=category_id).all()
        for item in items:
            session.delete(item)
        session.delete(category)
        session.commit()
        flash("category deleted")
        return redirect(url_for('listCategory'))
    else:
        return render_template('deletecategory.html',
                               category=category,
                               isLoggedIn=isLoggedIn())


# LIST ITEM

@app.route('/category/<int:category_id>/item')
@app.route('/category/<int:category_id>')
def listItem(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id)
    itemHeading = category.name + " Items"
    categories = session.query(Category).all()
    if 'logged_in' in login_session:
        return render_template('listcategoryloggedin.html',
                               categories=categories, items=items,
                               itemHeading=itemHeading,
                               isLoggedIn=isLoggedIn(),
                               isAdmin=isLoggedInAdmin())
    else:
        return render_template('listcategory.html',
                               categories=categories, items=items,
                               itemHeading=itemHeading,
                               isLoggedIn=isLoggedIn(),
                               isAdmin=isLoggedInAdmin())


# SHOW ITEM

# @app.route('/category/<int:category_id>/item/<int:item_id>')
@app.route('/item/<int:item_id>/')
def showItem(item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    if isLoggedInOwner(item.owner_id):
        return render_template('showitemloggedin.html',
                               item=item, isLoggedIn=isLoggedIn())
    else:
        return render_template('showitem.html',
                               item=item, isLoggedIn=isLoggedIn())


# NEW ITEM

@app.route('/item/new/', methods=['GET', 'POST'])
def newItem():
    # check user right to create a new  item
    if not isLoggedIn():
        msg = "you are not logged in or "
        msg += "do not have the right to create a new item"
        flash(msg)
        return redirect(url_for('listCategory'))

    if request.method == 'POST':
        newItem = Item(
            name=request.form['name'],
            description=request.form['description'],
            category_id=request.form['category_id'],
            owner_id=login_session['user_id'],
            created_at=datetime.now())
        session.add(newItem)
        session.commit()
        flash("new item created")
        return redirect(url_for('listItem', category_id=newItem.category_id))
    else:
        categories = session.query(Category).all()
        if not categories:
            msg = "no category found to create an item for; "
            msg += "create a category first"
            flash(msg)
            return redirect(url_for('listCategory'))
        return render_template('newitem.html',
                               categories=categories, isLoggedIn=isLoggedIn())


# EDIT ITEM

@app.route('/item/<int:item_id>/edit/', methods=['GET', 'POST'])
def editItem(item_id):

    # check whether item can be found
    try:
        item = session.query(Item).filter_by(id=item_id).one()
    except NoResultFound, e:
        flash('the item to be edited could not be found')
        return redirect(url_for('listCategory'))

    # check user right to edit the item
    if not isLoggedInOwner(item.owner_id):
        msg = "you are not logged in or "
        msg += "do not have the right to edit the item"
        flash(msg)
        return render_template('showitem.html',
                               item=item, isLoggedIn=isLoggedIn())

    if request.method == 'POST':
        # POST
        if (request.form['name']):
            item.name = request.form['name']
        if (request.form['description']):
            item.description = request.form['description']
        if (request.form['category_id']):
            item.category_id = request.form['category_id']
        session.add(item)
        session.commit()
        flash("item modified")
        return redirect(url_for('listItem', category_id=item.category_id,
                                isLoggedIn=isLoggedIn()))
    else:
        # GET
        categories = session.query(Category).all()
        return render_template('edititem.html',
                               item=item, categories=categories,
                               isLoggedIn=isLoggedIn())


# DELETE ITEM

@app.route('/item/<int:item_id>/delete/', methods=['GET', 'POST'])
def deleteItem(item_id):

    # check whether item can be found
    try:
        item = session.query(Item).filter_by(id=item_id).one()
    except NoResultFound, e:
        flash('the item to be delete can not be found')
        return redirect(url_for('listCategory'))

    # check user right to delete the item
    if not isLoggedInOwner(item.owner_id):
        msg = "you are not logged in or "
        msg += "do not have the right to edit the item"
        flash(msg)
        return render_template('showitem.html',
                               item=item, isLoggedIn=isLoggedIn())

    if request.method == 'POST':
        category_id = item.category_id
        session.delete(item)
        session.commit()
        flash("item deleted")
        return redirect(url_for('listItem',
                                category_id=category_id,
                                isLoggedIn=isLoggedIn()))
    else:
        return render_template('deleteitem.html',
                               item=item, isLoggedIn=isLoggedIn())


# USER LOGIN

@app.route('/user/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # POST
        if request.form['username'] and request.form['password']:
            # username and password given
            username = request.form['username']
            try:
                user = session.query(User).filter_by(name=username).one()

                # user found (no exception)
                # check password

		m = hashlib.md5()
		m.update(request.form['password'])
		md5Passwd = m.hexdigest()

                if user.password != md5Passwd:
                    flash('wrong password for user ' + username)
                else:
                    # password correct
                    login_session['logged_in'] = True
                    login_session['user_id'] = str(user.id)

                    if (user.role.name == "admin"):
                        login_session['admin_user'] = True

                    if 'admin_user' in login_session:
                        flash("you logged in sucessfully as admin")
                    else:
                        flash("you logged in sucessfully")

            except NoResultFound, e:
                # user is unknown (exception)
                flash("user " + username + " is not a registered user")
        else:
            # no username or no password entered
            flash("no username or no password entered for login")
        return redirect(url_for('listCategory'))

    else:
        # GET
        if 'logged_in' in login_session:
            flash("you are already logged in")
            return redirect(url_for('listCategory'))
        else:
            return render_template('login.html')


# USER LOGOUT

@app.route('/user/logout', methods=['GET', 'POST'])
def logout():
    login_session.pop('logged_in', None)
    login_session.pop('admin_user', None)
    login_session.pop('user_id', None)

    # if logged in via Google+ disconnect
    if 'gplus_id' in login_session:
            gdisconnect()

    flash('you are logged out')
    return redirect(url_for('listCategory'))


# USER REGISTER

@app.route('/user/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # POST
        if not request.form['username']:
            flash('username missing')
        if not request.form['password']:
            flash('password missing')
        if not request.form['username'] or not request.form['password']:
            return redirect('/user/register')

        else:
            # check whether user name already in use
            try:
                userName = request.form['username']
                user = session.query(User).filter_by(name=userName).one()
            except NoResultFound, e:
                # username not used yet -> may be used

		m = hashlib.md5()
		m.update(request.form['password'])
		md5Passwd = m.hexdigest()

                role = session.query(Role).filter_by(name="standard").one()
                newUser = User(
                    name=userName,
                    password=md5Passwd,
                    role=role,
                    created_at=datetime.now())
                session.add(newUser)
                session.commit()
                login_session['logged_in'] = True
                login_session['user_id'] = str(newUser.id)
                flash("you were registered as new user and are logged in")
                return redirect(url_for('listCategory'))
            # user name already in use
            flash("user " + request.form['username'] +
                  " is used already. Please choose another user name.")
            return render_template('register.html')

    else:
        # GET
        return render_template('register.html')


# --- JSON ---

# CATEGORY LIST JSON

@app.route('/category/JSON')
def listCategoryJSON():
    categories = session.query(Category).all()
    return jsonify(Categories=[c.serialize for c in categories])


# CATEGORY JSON

@app.route('/category/<int:category_id>/JSON')
def showCategoryJSON(category_id):
    category = session.query(Category).filter_by(
        id=category_id).one()
    return jsonify(Categories=[category.serialize])


# ITEM LIST JSON

@app.route('/item/JSON')
def listItemJSON():
    items = session.query(Item).all()
    return jsonify(Items=[i.serialize for i in items])


# ITEM OF CATEGORY LIST JSON

@app.route('/category/<int:category_id>/item/JSON')
def itemJSON(category_id):
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/item/<int:item_id>/JSON')
def showItemJSON(item_id):
    items = session.query(Item).filter_by(
        id=item_id).one()
    return jsonify(Items=[i.serialize for i in items])


# USER LIST JSON

@app.route('/user/JSON')
def listUserJSON():
    if not isLoggedInAdmin():
	return "authorization as admin user required"
    users = session.query(User).all()
    return jsonify(Users=[u.serialize for u in users])


# USER JSON
@app.route('/user/<int:user_id>/JSON')
def userJSON(user_id):
    if not isLoggedInAdmin():
	return "authorization as admin user required"
    user = session.query(User).filter_by(
        id=user_id).one()
    return jsonify(Users=[user.serialize])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
