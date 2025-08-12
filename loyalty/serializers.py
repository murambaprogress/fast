from rest_framework import serializers
from .models import LoyaltyAccount, LoyaltyTransaction, PointRedemption

class LoyaltyAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoyaltyAccount
        fields = '__all__'

class LoyaltyTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoyaltyTransaction
        fields = '__all__'

class PointRedemptionSerializer(serializers.ModelSerializer):
    user_phone = serializers.CharField(source='user.phone_number', read_only=True)
    user_name = serializers.SerializerMethodField()
    
    class Meta:
        model = PointRedemption
        fields = '__all__'
    
    def get_user_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.phone_number

class RedemptionCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = PointRedemption
        fields = ['redemption_type', 'flight_route', 'preferred_date']
    
    def validate(self, data):
        user = self.context['request'].user
        loyalty_account = getattr(user, 'loyalty_account', None)
        
        if not loyalty_account:
            raise serializers.ValidationError("User doesn't have a loyalty account")
        
        # Check points based on redemption type
        points_required = {
            'free_flight': 1000,  # Threshold now 1000 for free flight
            'wallet_credit': 500,
            'priority_boarding': 150,
            'lounge_access': 700,
            'extra_baggage': 300,
        }
        
        required = points_required.get(data['redemption_type'], 500)
        if loyalty_account.points < required:
            raise serializers.ValidationError(
                f"Insufficient points. Required: {required}, Available: {loyalty_account.points}"
            )
        
        data['points_required'] = required
        return data
    
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)
