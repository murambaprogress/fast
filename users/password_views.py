from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.hashers import check_password
from django.contrib.auth import get_user_model

User = get_user_model()

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_password(request):
    """
    Verify a user's password for sensitive operations
    """
    password = request.data.get('password')
    
    if not password:
        return Response({'error': 'Password is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Get the current authenticated user
    user = request.user
    
    # Check if the provided password matches
    if check_password(password, user.password):
        return Response({'success': True}, status=status.HTTP_200_OK)
    else:
        # Return 401 for security reasons (not revealing if the password is wrong)
        return Response({'error': 'Invalid password'}, status=status.HTTP_401_UNAUTHORIZED)
