from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, Role, User
from datetime import datetime

engine = create_engine('sqlite:///category_item.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()


# Insert roles in the database role table

roleAdmin = Role(name="admin")
roleStandard = Role(name="standard")

session.add(roleAdmin)
session.add(roleStandard)

session.commit()
