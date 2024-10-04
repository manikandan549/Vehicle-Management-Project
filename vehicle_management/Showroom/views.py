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






from rest_framework.permissions import IsAuthenticated
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
            return Response({"message": "Logged in successfully", "username": user.username,"role": user.role,"Login_at":current_time}, status=status.HTTP_200_OK)
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
    permission_classes = [IsCustomer | IsAdminOrReadOnly]

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



class ScheduleServicesView(APIView):
    permission_classes = [IsAuthenticated, IsServiceAgent | IsAdminOrReadOnly]
    
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


