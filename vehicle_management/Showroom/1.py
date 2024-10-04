from django.contrib.auth.models import AbstractUser
from django.db import models
from datetime import date

class Users(AbstractUser):
    # User_id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=255,unique=True)
    password = models.CharField(max_length=255)
    role = models.CharField(max_length=40, choices= [('Showroom_Owner', 'Showroom Owner'),('Service_Agent', 'Service Agent'),('Customer', 'Customer')])
    email = models.EmailField(max_length=150)

    def __str__(self):
        return self.username

class Vehicle(models.Model):
    vehicle_id = models.IntegerField(primary_key=True) 
    brand = models.CharField(max_length=100)
    vehicle = models.CharField(max_length=100,unique=True)
    model_year = models.PositiveIntegerField()
    color = models.CharField(max_length=50)
    specifications = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    quantity = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.brand} {self.vehicle}"

class AssignVehicle(models.Model):
    Assign_id = models.AutoField(primary_key=True) 
    customer = models.ForeignKey(Users,limit_choices_to={'role': 'Customer'}, on_delete=models.CASCADE, related_name='AssignVehicle',to_field="username")
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE, related_name='AssignVehicle',to_field="vehicle")
    vehicles_id = models.IntegerField() 
    quantity = models.IntegerField()
    assigned_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if self.vehicle:
            self.vehicles_id = self.vehicle.vehicle_id
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.vehicle} assigned to {self.customer}"

class CustomerVehicle(models.Model):
    customer_vehicle_id = models.AutoField(primary_key=True) 
    customer = models.ForeignKey(Users,limit_choices_to={'role': 'Customer'}, on_delete=models.CASCADE, related_name='CustomerVehicle',to_field="username")
    customer_vehicle = models.CharField(max_length=255,unique=True)
    vehicle_number = models.CharField(max_length=25)
    service_Due_date = models.DateField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.customer_vehicle} ({self.vehicle_number})"

class ServiceRequest(models.Model):
    service_request_id = models.AutoField(primary_key=True) 
    customer_vehicle = models.ForeignKey(CustomerVehicle, on_delete=models.CASCADE, related_name='service_requests',to_field="customer_vehicle")
    customer = models.ForeignKey(Users,limit_choices_to={'role': 'Customer'},on_delete=models.CASCADE, related_name='service_requestt', null=True, blank=True,to_field="username")
    service_type = models.CharField(max_length=40, choices=[('Full_Service', 'Full Service'),('Regular_Service', 'Regular Service'),('Customize_Service', 'Customize Service')], default='Regular_Service')
    service_scheduled_date = models.DateField(null=True)
    scheduled_by = models.ForeignKey(Users,limit_choices_to={'role': 'Service_Agent'},on_delete=models.CASCADE, related_name='service_request', null=True, blank=True,to_field="username")
    status_of_request = models.CharField(max_length=40, choices=[('Pending', 'Pending'),('Confirmed', 'Confirmed'),('Cancelled', 'Cancelled')], default='Pending',null=True)
    request_at = models.DateField(default=date.today)
    
    def save(self, *args, **kwargs):
        if self.customer_vehicle:
            self.customer = self.customer_vehicle.customer
        super().save(*args, **kwargs)


class Service(models.Model):
    service_id = models.AutoField(primary_key=True) 
    service_request_id = models.ForeignKey(ServiceRequest, on_delete=models.CASCADE, related_name='services',to_field="service_request_id")
    service_date = models.DateField(null=True, blank=True)
    service_type = models.CharField(max_length=350,null=True)
    description = models.TextField(null=True, blank=True,max_length=400)
    status = models.CharField(max_length=40, choices=[('Pending', 'Pending'),('In_Progress', 'In Progress'), ('Completed', 'Completed')], default='Pending')
    next_service_date = models.DateField(null=True, blank=True)
    performed_by = models.ForeignKey(Users,limit_choices_to={'role': 'Service_Agent'},on_delete=models.CASCADE, related_name='servicesss', null=True, blank=True,to_field="username")


    def save(self, *args, **kwargs):
        if self.service_request_id:
            self.service_type = self.service_request_id.service_type
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"Service for {self.service_request_id.customer_vehicle} on {self.service_date}"


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

from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings
from rest_framework.views import APIView
from django.contrib.auth import update_session_auth_hash, get_user_model
from django.contrib.auth.forms import SetPasswordForm
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views import View
from django.utils import timezone
from datetime import datetime as dt, timedelta
from django.db.models import Sum, F, FloatField
from django.db.models.functions import Cast
from .utils import send_service_scheduled_email






from rest_framework import generics, permissions, status
from rest_framework.response import Response
from django.contrib.auth import authenticate, login, logout
from django.utils import timezone
from datetime import datetime
from .models import *
from .serializers import *
from .permissions import *

User = get_user_model()

class RegisterUser(generics.ListCreateAPIView):
    queryset = Users.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]  

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email')
        role = request.data.get('role')

        if Users.objects.filter(username=username).exists():
            return Response({"error": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST)

        user = Users.objects.create_user(username=username, email=email, role=role, password=password)
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)

class Userupdate(generics.UpdateAPIView):
    queryset = Users.objects.all()
    serializer_class = UserupdateSerializer
    permission_classes = [permissions.AllowAny]  
    lookup_field = 'id' 

class ChangePasswordView(generics.GenericAPIView):
    
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated] 

    def post(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            old_password = serializer.validated_data['old_password']
            new_password1 = serializer.validated_data['new_password1']

           
            if not user.check_password(old_password):
                return Response({"old_password": ["Old password is incorrect."]}, status=status.HTTP_400_BAD_REQUEST)

           
            form = SetPasswordForm(user=user, data={
                'new_password1': new_password1,
                'new_password2': serializer.validated_data['new_password2']
            })
            if form.is_valid():
                form.save()
                update_session_auth_hash(request, user) 
                return Response({"detail": "Password has been updated successfully."}, status=status.HTTP_200_OK)
            else:
                return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class LoginUser(generics.CreateAPIView):
    queryset = Users.objects.all()
    serializer_class = UserLoginSerializer
    permission_classes = [permissions.AllowAny]  

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            current_time = datetime.now().isoformat()
            return Response({"message": "Logged in successfully", "username": user.username,"Login_at":current_time}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
            self.send_password_reset_email(user, request)
            return Response({"detail": "Password reset email sent."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def send_password_reset_email(self, user, request):
        token_generator = default_token_generator
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)
        domain = get_current_site(request).domain
        link = f"http://{domain}/reset-password/{uid}/{token}/"
        subject = "Password Reset Request"
        message = render_to_string('password_reset_email.html', {
            'user': user,
            'reset_link': link,
        })
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer
    def post(self, request, uidb64, token, *args, **kwargs):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"detail": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST)

        if default_token_generator.check_token(user, token):
            form = SetPasswordForm(user, data=request.data)
            if form.is_valid():
                form.save()
                return Response({"detail": "Password has been reset successfully."}, status=status.HTTP_200_OK)
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"detail": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST)

class LogoutUser(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        username = request.user.username if request.user.is_authenticated else None
        logout(request)
        current_time = datetime.now().isoformat()
        return Response({"message": "Logged out successfully", "username": username,"Logout_at":current_time}, status=status.HTTP_200_OK)



class VehicleListCreateView(generics.ListCreateAPIView):
    queryset = Vehicle.objects.all()
    serializer_class = VehicleSerializer
    permission_classes = [IsShowroomOwner | IsAdminOrReadOnly]

class VehicleRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Vehicle.objects.all()
    serializer_class = VehicleSerializer
    permission_classes = [IsShowroomOwner | IsAdminOrReadOnly]


class VehicleinventoryView(generics.ListAPIView):
    queryset = Vehicle.objects.all()
    serializer_class = VehicleSerializer
    permission_classes = [IsShowroomOwner | IsAdminOrReadOnly]



class AssignVehicleListCreateView(generics.ListCreateAPIView):
    queryset = AssignVehicle.objects.all()
    serializer_class = AssignVehicleSerializer
    permission_classes = [IsShowroomOwner | IsAdminOrReadOnly]

    def post(self, request, *args, **kwargs):
        vehicle_name = request.data.get('vehicle')
        quantity_assign = request.data.get('quantity')

        if not vehicle_name or not quantity_assign:
            return Response('Both vehicle_name and quantity_assign are required.', status=status.HTTP_400_BAD_REQUEST)

        try:
            vehicle = Vehicle.objects.get(vehicle=vehicle_name)
        except Vehicle.DoesNotExist:
            return Response(f'Vehicle with name "{vehicle_name}" does not exist.', status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response(str(e), status=status.HTTP_400_BAD_REQUEST)

        try:
            quantity_assign = int(quantity_assign)
        except ValueError:
            raise ValidationError("Invalid quantity specified. Quantity must be an integer.")

        if vehicle.quantity is None:
            return Response(f'Stock information for "{vehicle_name}" is unavailable. Contact support.', status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        current_stock = vehicle.quantity

        if current_stock >= quantity_assign:
            vehicle.quantity -= quantity_assign
            vehicle.save()
            serializer = AssignVehicleSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(f'Not enough stock for "{vehicle_name}". Current stock is {current_stock}.', status=status.HTTP_400_BAD_REQUEST)

class AssignVehicleRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = AssignVehicle.objects.all()
    serializer_class = AssignVehicleSerializer
    permission_classes = [IsShowroomOwner | IsAdminOrReadOnly]



class CustomerVehicleListCreateView(generics.ListCreateAPIView):
    queryset = CustomerVehicle.objects.all()
    serializer_class = CustomerVehicleSerializer
    permission_classes = [IsCustomer | IsAdminOrReadOnly]


class CustomerVehicleRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = CustomerVehicle.objects.all()
    serializer_class = CustomerVehicleSerializer
    permission_classes = [IsCustomer | IsAdminOrReadOnly]



class ServiceListCreateView(generics.ListCreateAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [IsCustomer | IsServiceAgent | IsAdminOrReadOnly]

class ServiceRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [IsServiceAgent | IsAdminOrReadOnly]



class ServiceRequestListCreateView(generics.ListCreateAPIView):
    queryset = ServiceRequest.objects.all()
    serializer_class = ServiceRequestSerializer
    # permission_classes = [IsCustomer | IsAdminOrReadOnly]

class ServiceRequestRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = ServiceRequest.objects.all()
    serializer_class = ServiceRequestSerializer
    permission_classes = [IsCustomer | IsServiceAgent | IsAdminOrReadOnly]


def upcoming_services(request):
    
    permission_classes = [IsServiceAgent | IsAdminOrReadOnly]
    
    now = timezone.now()
    services = ServiceRequest.objects.filter(service_scheduled_date__gte=now).order_by('customer')

    services_list = list(services.values('customer', 'service_scheduled_date', 'service_request_id'))

    return JsonResponse({'Upcoming_Services': services_list})




def service_history(request):
    
    permission_classes = [IsCustomer | IsServiceAgent | IsAdminOrReadOnly]
    

    completed_services = Service.objects.filter(
        status='Completed'
    ).order_by('service_date')

    services_list = list(completed_services.values(
        'service_id', 'service_request_id','service_request_id__customer' ,'service_date', 'service_type', 'description', 'status', 'next_service_date', 'performed_by'
    ))

    return JsonResponse({'service_history': services_list})



def customer_service_history(request):
    
    permission_classes = [IsCustomer | IsServiceAgent | IsAdminOrReadOnly]
    
    user = request.user

    try:
        customer = user.username
        
    except:
        return JsonResponse({'error': 'Customer profile not found for this user'}, status=404)

    
    completed_services = Service.objects.filter(
        service_request_id__customer=customer,
        status='Completed'
    ).order_by('service_date')

    services_list = list(completed_services.values(
        'service_id', 'service_request_id','service_request_id__customer' ,'service_date', 'service_type', 'description', 'status', 'next_service_date', 'performed_by'
    ))

    return JsonResponse({'customer_service_history': services_list})



class SalesReportView(View):
    
    permission_classes = [IsShowroomOwner | IsAdminOrReadOnly]
    
    def get(self, request, *args, **kwargs):
    
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        days = kwargs.get('days', None)  
        
        
        try:
            report = self.generate_daily_sales_report(start_date=start_date, end_date=end_date, days=days)
        except ValueError as e:
            return JsonResponse({'error': str(e)}, status=400)
        
       
        return JsonResponse(report, safe=False)

    def generate_daily_sales_report(self, start_date=None, end_date=None, days=None):
        
        if days is not None:
            try:
                days = int(days)
            except ValueError:
                raise ValueError("Invalid value for 'days'. Must be an integer.")
            
            if days < 0:
                raise ValueError("'days' cannot be negative.")
            
            if days == 0:
            
                start_date = end_date = timezone.now().date().isoformat()
            else:
                if not start_date:
                    start_date = (timezone.now() - timedelta(days=days)).date().isoformat()
                if not end_date:
                    end_date = timezone.now().date().isoformat()
        else:
            if not start_date:
                start_date = (timezone.now() - timedelta(days=30)).date().isoformat()
            if not end_date:
                end_date = timezone.now().date().isoformat()

        
        try:
            if isinstance(start_date, str):
                start_date = dt.fromisoformat(start_date).date()
            if isinstance(end_date, str):
                end_date = dt.fromisoformat(end_date).date()
        except ValueError:
            raise ValueError("Invalid date format. Dates must be in 'YYYY-MM-DD' format.")

        
        sales_data = (AssignVehicle.objects
                      .filter(assigned_at__date__range=[start_date, end_date])
                      .select_related('vehicle')  
                      .values('assigned_at__date') 
                      .annotate(total_quantity=Sum('quantity'))
                      .annotate(total_revenue=Sum(Cast(F('quantity') * F('vehicle__price'), FloatField())))
                      .order_by('assigned_at__date'))

        
        report = []
        for entry in sales_data:
            report.append({
                'date': entry['assigned_at__date'],
                'total_quantity': entry['total_quantity'],
                'total_revenue': entry['total_revenue']
            })

        return ({'Sales_Report': report})



class ScheduleServicesView(View):
    permission_classes = [IsServiceAgent | IsAdminOrReadOnly]
    
    def get(self, request, *args, **kwargs):
        """
        Handle GET request to schedule services for a specific ServiceRequest ID
        and return a JSON response.
        """
        service_request_id = self.kwargs.get('service_request_id')
        
        if not service_request_id:
            return JsonResponse({'status': 'error', 'message': 'Service request ID not provided'}, status=400)
        
        user = request.user
        ServiceAgent = user.username
        if not user.is_authenticated or not (IsServiceAgent().has_permission(request, self) or IsAdminOrReadOnly().has_permission(request, self)):
            return JsonResponse({'status': 'error', 'message': 'Permission denied'}, status=403)

        try:
            result = schedule_services(service_request_id, ServiceAgent)
            response = {
                'status': 'success',
                'message': result
            }
            return JsonResponse(response, status=200)
        except Exception as e:
            response = {
                'status': 'error',
                'message': str(e)
            }
            return JsonResponse(response, status=500)


def schedule_services(service_request_id, ServiceAgent):
    """
    Schedule services based on the FIFO principle and service type constraints
    for a specific ServiceRequest ID.
    """
    max_services_per_day = {
        'Full_Service': 1,
        'Regular_Service': 3,
        'Customize_Service': 2
    }

    request = get_object_or_404(ServiceRequest, service_request_id=service_request_id)
    
    # Check if services are already scheduled
    if Service.objects.filter(service_request_id=request).exists():
        return "A service has already been scheduled for this request."

    # Check if request date is set
    if request.request_at is None:
        return "Request date is not set for this request."

    service_type = request.service_type
    if service_type not in max_services_per_day:
        raise ValueError('Invalid service type')

    daily_limit = max_services_per_day[service_type]
    start_date = request.request_at + timedelta(days=1)
    number_of_services_to_schedule = 1  # You can adjust this if needed

    current_date = start_date
    first_service_date = None
    
    try:
        ServiceAgent = User.objects.get(username=ServiceAgent)
    except User.DoesNotExist:
        return "ServiceAgent user does not exist."

    while number_of_services_to_schedule > 0:
        existing_services_count = Service.objects.filter(
            service_date=current_date,
            service_type=service_type
        ).count()

        available_slots = daily_limit - existing_services_count

        if available_slots > 0:
            services_to_create = min(available_slots, number_of_services_to_schedule)
            
            services = [
                Service(
                    service_request_id=request, 
                    service_date=current_date,
                    service_type=service_type,
                )
                for _ in range(services_to_create)
            ]
            Service.objects.bulk_create(services)
            
            if first_service_date is None:
                first_service_date = current_date
            
            number_of_services_to_schedule -= services_to_create
        
        if number_of_services_to_schedule > 0:
            current_date += timedelta(days=1)

    if first_service_date:
        request.service_scheduled_date = first_service_date
        request.status_of_request = 'Confirmed'
        request.scheduled_by=ServiceAgent
        request.save()
    
    # send_service_scheduled_email(request)  # Uncomment if email notifications are needed
    return "Service scheduling completed."


from rest_framework.permissions import BasePermission
from rest_framework import permissions
from rest_framework import generics

class IsShowroomOwner(BasePermission):
    """
    Custom permission to only allow showroom owners to access certain views.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'Showroom_Owner'

class IsServiceAgent(BasePermission):
    """
    Custom permission to only allow service agents to access certain views.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'Service_Agent'

class IsCustomer(BasePermission):
    """
    Custom permission to only allow customers to access certain views.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'Customer'

class IsAdminOrReadOnly(BasePermission):
    """
    Custom permission to only allow admin users to edit objects.
    Others can only read.
    """
    def has_permission(self, request, view):
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True

        return request.user.is_authenticated and request.user.is_staff


from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import *

urlpatterns = [
    path('register/', RegisterUser.as_view(), name='register'),
    path('Userupdate/<int:id>', Userupdate.as_view(), name='reset'),
    path('password-reset/', PasswordResetView.as_view(), name='password_reset'),
    path('reset-password/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('login/', LoginUser.as_view(), name='login'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('logout/', LogoutUser.as_view(), name='logout'),

    path('vehicle/', VehicleListCreateView.as_view(), name='vehicle-list-create'),
    path('vehicle/<int:pk>/', VehicleRetrieveUpdateDestroyView.as_view(), name='vehicle-detail'),

    path('assign_vehicle/', AssignVehicleListCreateView.as_view(), name='assign-vehicle-list-create'),
    path('assign-vehicle/<int:pk>/', AssignVehicleRetrieveUpdateDestroyView.as_view(), name='assign-vehicle-detail'),

    path('customer-vehicle/', CustomerVehicleListCreateView.as_view(), name='customer-vehicle-list-create'),
    path('customer-vehicle/<int:pk>/', CustomerVehicleRetrieveUpdateDestroyView.as_view(), name='customer-vehicle-detail'),

    path('service/', ServiceListCreateView.as_view(), name='service-list-create'),
    path('service/<int:pk>/', ServiceRetrieveUpdateDestroyView.as_view(), name='service-detail'),

    path('service-request/', ServiceRequestListCreateView.as_view(), name='service-request-list-create'),
    path('service-request/<int:pk>/', ServiceRequestRetrieveUpdateDestroyView.as_view(), name='service-request-detail'),

    
    path('Vehicle-inventory/', VehicleinventoryView.as_view(), name='Vehicleinventory'),
    
    path('sales-report/<int:days>/', SalesReportView.as_view(), name='sales-report'),
    
    path('schedule-services/<int:service_request_id>/', ScheduleServicesView.as_view(), name='schedule_services'),
    
    path('upcoming-services/', upcoming_services, name='upcoming_services'),
    
    path('service-history/', service_history, name='service_history'),
    
    
    path('customer_service_history/', customer_service_history, name='customer_service_history'),
    
    
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), 
    
]

