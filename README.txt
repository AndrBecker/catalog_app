
	Item-catalog project for Udacity


--- Introduction ---

This application follows the specification of the item-catalog project
of the Udacity P3 project for the Udacity Fullstack Webdeveloper
Nanodegree. The application allows for the administration of
categories and associated items.



--- User categories ---

The application distinguishes three types of users defined by
their rights to manage items in the application.

An anonymous, unregistered user may look at categories and items
created by registered user. An unregistered user can not
create items.

A registered standard user can create, edit and delete items that
belong to that user. Internally the standard user is associated with
the "standard"-role.

A registered admin user has the rights of the registered standard
user but can also create, edit and delete categories. The admin user
is associated with the "admin"-role. An registered user 
can only become an admin user by execution of the admin_create.py
script (see below).



--- Installation ---

1. Set up the database by executing the database setup script:

	python database_setup.py

This creates an sqlite-database containing the schema of the
item-catalog application.


2. Initialize the database with a few entries by executing the
script database_fill.py:

	python database_fill.py

The database table "role" is filled with the two predefined
roles "admin" and "standard". 


3. An admin user is created by executing the admin_create.py
script. This script can only be run after the execution of
the database_fill.py script. Before execution the admin user's
name and password should be entered in the placeholders
"TODO_EDIT_ADMIN_NAME" and "TODO_EDIT_ADMIN_PASSWORD" respectively.
Note that the current version of the item-category-server
does not encipher passwords in the database.

	python admin_create.py


4. Flask Session security

In the application.py script the app.secret_key is to be
set to a non-trivial character sequence. This key is used to 
encipher the contents of the Flask session object.

	app.secret_key = 'super_secret_key'




3. Identification by Google Oauth

The application supports identification via Google+-Id
and the local registration of users in the database.

For Google Oauth a client secret file with the
name 'client_secrets.json' is to be placed in the same
directory where the application is started.

The client id contained in the client secret file is to
be inserted in the login.html file as value of variable
data-clientid:

	data-clientid="XXXX.apps.googleusercontent.com"



4. Start the application by executing script application.py:

	python application.py

The application is run on localhost on port 8000. It can
be accessed typing http://localhost:8000 in the address line
of a browser. The application can be terminated by typing
Ctrl-C in the shell running the application script.




--- JSON Interfaces ---

The application includes JSON-interfaces under the following addresses.
Note that in the current version the access to the JSON-interfaces
and thus to the database contents is not restricted.


- all categories:
/category/JSON


- single category:
/category/<int:category_id>/JSON


- all items:
/item/JSON


- all items of a catgory:
/category/<int:category_id>/item/JSON


- single item:
/item/<int:item_id>/JSON


- all users:
/user/JSON


- single user:
/user/<int:user_id>/JSON


