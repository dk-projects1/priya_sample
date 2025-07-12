from django.urls import converters
from bson import ObjectId

class ObjectIdConverter(converters.StringConverter):
    regex = '[a-fA-F0-9]{24}'

    def to_python(self, value):
        return ObjectId(value)

    def to_url(self, value):
        return str(value)
