#!/usr/bin/env python

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import City, Base, Attraction, User

engine = create_engine('postgresql://catalog:catalog@localhost/catalog')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

# create dummy users


User1 = User(name="Emily Martin", email="emily.martin88@gmail.com")
session.add(User1)
session.commit()

# city 1 and its attractions

city1 = City(user_id=1, name="New York City")

session.add(city1)
session.commit()

description1 = """The Statue of Liberty Enlightening
    the World was a gift of friendship from the people of France
    to the people of the United States and is a universal
    symbol of freedom and democracy. The Statue of Liberty was
    dedicated on October 28, 1886, designated as a National
    Monument in 1924 and restored for her centennial on July 4, 1986."""

attraction1 = Attraction(user_id=1, name="Statue of Liberty",
                         description=description1, city=city1)

session.add(attraction1)
session.commit()

description2 = """The Empire State Building is the World's Most
               Famous Office Building. Named America's favorite
               building in a poll conducted by the American Institute
               of Architects, the Empire State Building is one
               of New York City's top tourist destinations."""

attraction2 = Attraction(user_id=1, name="Empire State Building",
                         description=description2, city=city1)

session.add(attraction2)
session.commit()

description3 = """For more than 150 years, visitors have flocked
               to Central Park's 843 green acres in the heart of Manhattan."""

attraction3 = Attraction(user_id=1, name="Central Park",
                         description=description3, city=city1)

session.add(attraction3)
session.commit()

# city 2 and its attractions

city2 = City(user_id=1, name="Beijing")

session.add(city2)
session.commit()

description4 = """The Great Wall of China is considered to be the only
               man-made project visible from the moon. Although it was
               once thought to have been built entirely during the Qin
               Dynasty between 221 and 238 BC, it is now believed to
               have been started earlier. Stretching more than 6,400
               kilometers in length."""

attraction4 = Attraction(user_id=1, name="The Great Wall at Badaling",
                         description=description4, city=city2)

session.add(attraction4)
session.commit()

description5 = """Consisting of more than 9,000 rooms and spread over
               250 acres, this huge palace complex was built in the
               15th century and later extensively renovated and restored
               during the Qing Dynasty in the 18th century"""

attraction5 = Attraction(user_id=1, name="Forbidden City",
                         description=description5, city=city2)

session.add(attraction5)
session.commit()

print ("added cities and attractions!")
