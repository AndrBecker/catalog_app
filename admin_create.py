from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from datetime import datetime
from database_setup import Base, Category, Item, Role, User
import hashlib

engine = create_engine('sqlite:///category_item.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()


# Add admin user

adminName="TODO_EDIT_ADMIN_NAME"
adminPassword="TODO_EDIT_ADMIN_PASSWORD"

m = hashlib.md5()
m.update(adminPassword)
md5Passwd = m.hexdigest()

try:
    roleAdmin = session.query(Role).filter_by(name="admin").one()

    userAdmin = User(name=adminName,
                     password=md5Passwd,
                     role=roleAdmin, created_at=datetime.now())

    session.add(userAdmin)
    session.commit()

    print "admin user created in the database."

except NoResultFound, e:
    print '''Error: Fill database with role definitions first
        before creating an admin user.'''
