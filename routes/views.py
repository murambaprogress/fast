# routes/views.py
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import Route
from rest_framework.decorators import api_view, permission_classes
from .serializers import RouteSerializer
from rest_framework.permissions import AllowAny

@api_view(['GET', 'POST'])
@permission_classes([AllowAny]) 
def routes_list_create(request):
    if request.method == 'GET':
        routes = Route.objects.all()
        serializer = RouteSerializer(routes, many=True, context={'request': request})
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = RouteSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT', 'DELETE'])
@permission_classes([AllowAny])
def route_detail(request, pk):
    try:
        route = Route.objects.get(pk=pk)
    except Route.DoesNotExist:
        return Response({'error': 'Route not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([AllowAny])
def routes_for_selection(request):
    """
    Get a list of routes optimized for selection in dropdowns
    """
    routes = Route.objects.all().order_by('from_destination__name', 'to_destination__name')
    serializer = RouteSerializer(routes, many=True, context={'request': request})
    return Response(serializer.data)

    if request.method == 'PUT':
        serializer = RouteSerializer(route, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        route.delete()
        return Response({'message': 'Route deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
