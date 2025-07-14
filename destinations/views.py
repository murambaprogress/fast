from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from .serializers import DestinationSerializer
from .models import Destination  # ✅ Correct import

@api_view(['GET'])
def get_destinations(request):
    destinations = Destination.objects.all()
    serializer = DestinationSerializer(destinations, many=True, context={'request': request})
    return Response(serializer.data)

@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def create_destination(request):
    serializer = DestinationSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=201)
    return Response(serializer.errors, status=400)
