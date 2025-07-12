from djongo.models import Model, ObjectIdField, CharField, IntegerField


class User(Model):
    _id = ObjectIdField()
    username = CharField(max_length=100)
    password = CharField(max_length=128)
    email = CharField(max_length=100)

class Admin(Model):
    _id = ObjectIdField()
    username = CharField(max_length=100)
    password = CharField(max_length=128)

class Post(Model):
    _id = ObjectIdField()
    title = CharField(max_length=100)
    des = CharField(max_length=1000)
    image = CharField(max_length=128)
    price = CharField(max_length=10000)

    