# routes/serializers.py
from rest_framework import serializers
from .models import Route
from destinations.models import Destination

class DestinationSimpleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Destination
        fields = ['id', 'name']

class RouteSerializer(serializers.ModelSerializer):
    from_destination = DestinationSimpleSerializer(read_only=True)
    to_destination = DestinationSimpleSerializer(read_only=True)

    from_destination_id = serializers.PrimaryKeyRelatedField(
        queryset=Destination.objects.all(), source='from_destination', write_only=True
    )
    to_destination_id = serializers.PrimaryKeyRelatedField(
        queryset=Destination.objects.all(), source='to_destination', write_only=True
    )

    class Meta:
        model = Route
        fields = [
            'id',
            'from_destination', 'to_destination',
            'from_destination_id', 'to_destination_id',
            'point_threshold', 'price',  'currency', 'estimated_time', 'distance',
            
        ]
