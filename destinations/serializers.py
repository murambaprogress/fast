from rest_framework import serializers
from .models import Destination

class DestinationSerializer(serializers.ModelSerializer):
    picture = serializers.SerializerMethodField()

    class Meta:
        model = Destination
        fields = [
            'id', 'name', 'subdestinations', 'latitude',
            'longitude', 'map_link', 'picture'
        ]

    def get_picture(self, obj):
        request = self.context.get('request')
        if obj.picture and request:
            return request.build_absolute_uri(obj.picture.url)
        elif obj.picture:
            return obj.picture.url
        return None
