from rest_framework import serializers
from .models import *
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.forms import SetPasswordForm
from django.utils import timezone

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['id', 'username', 'password','role','email']
        extra_kwargs = {
            'password': {'write_only': True}, 
        }
        
    def create(self, validated_data):
        password = validated_data.pop('password',None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance

class UserLoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['id', 'username', 'password']


class UserupdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['email']
        

class VehicleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vehicle
        fields = ['vehicle_id', 'brand', 'vehicle', 'model_year', 'color', 'specifications', 'price', 'quantity', 'created_at']

class VehicleupdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vehicle
        fields = ['vehicle']




class AssignVehicleSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssignVehicle
        fields = ['Assign_id', 'customer','vehicle', 'quantity', 'assigned_at']


class CustomerVehicleSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerVehicle
        fields = ['customer_vehicle_id', 'customer', 'customer_vehicle', 'vehicle_number', 'service_Due_date']


class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = ['service_id', 'service_request_id', 'service_date', 'service_type', 'description', 'status', 'next_service_date', 'performed_by']


class ServiceRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceRequest
        fields = ['service_request_id', 'customer_vehicle','customer', 'service_type', 'service_scheduled_date', 'scheduled_by', 'status_of_request','request_at']


class UpcomingServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerVehicle
        fields = ['customer_vehicle_id', 'customer_vehicle', 'customer', 'service_Due_date']
        

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            User.objects.get(email=value)
        except ObjectDoesNotExist:
            raise serializers.ValidationError("No user with this email address exists.")
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password1 = serializers.CharField(write_only=True, required=True)
    new_password2 = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        if data['new_password1'] != data['new_password2']:
            raise serializers.ValidationError("Passwords must match.")
        return data



class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password1 = serializers.CharField(required=True)
    new_password2 = serializers.CharField(required=True)

    def validate(self, data):
        if data['new_password1'] != data['new_password2']:
            raise serializers.ValidationError({'new_password2': 'The two password fields must match.'})
        return data
