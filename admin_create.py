from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from datetime import datetime
from database_setup import Base, Category, Item, Role, User


engine = create_engine('sqlite:///category_item.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()


# Add admin user

try:
    roleAdmin = session.query(Role).filter_by(name="admin").one()

    userAdmin = User(name="TODO_EDIT_ADMIN_NAME",
                     password="TODO_EDIT_ADMIN_PASSWORD",
                     role=roleAdmin, created_at=datetime.now())

    session.add(userAdmin)
    session.commit()

    print "admin user created in the database."

except NoResultFound, e:
    print '''Error: Fill database with role definitions first
        before creating an admin user.'''
