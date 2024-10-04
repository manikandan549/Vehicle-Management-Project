# # from django.shortcuts import render

# # # Create your views here.
# # from rest_framework import viewsets
# # from .models import *
# # from .serializers import *

# # class UserViewSet(viewsets.ModelViewSet):
# #     queryset = User.objects.all()
# #     serializer_class = UserSerializer

# # class VehicleViewSet(viewsets.ModelViewSet):
# #     queryset = Vehicle.objects.all()
# #     serializer_class = VehicleSerializer

# # class AssignvehicleViewSet(viewsets.ModelViewSet):
# #     queryset = AssignVehicle.objects.all()
# #     serializer_class = AssignvehicleSerializer

# # class CustomervehViewSet(viewsets.ModelViewSet):
# #     queryset = CustomerVehicle.objects.all()
# #     serializer_class = CustomervehSerializer

# # class UpcomingServiceViewSet(viewsets.ReadOnlyModelViewSet):
# #     queryset = CustomerVehicle.objects.all()
# #     serializer_class = UpcomingServiceSerializer

# # class ServiceViewSet(viewsets.ModelViewSet):
# #     queryset = Service.objects.all()
# #     serializer_class = ServiceSerializer

# # class ServiceRequestViewSet(viewsets.ModelViewSet):
# #     queryset = ServiceRequest.objects.all()
# #     serializer_class = ServiceRequestSerializer

# # class ServiceScheduleViewSet(viewsets.ModelViewSet):
# #     queryset = ServiceRequest.objects.all()
# #     serializer_class = ServiceScheduleSerializer

# # views.py

# # from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

# # You don't need to write any additional code here
# # Just use the views provided by simplejwt

# # class MyTokenObtainPairView(TokenObtainPairView):
# #     # Optionally, override the default behavior
# #     pass

# # class MyTokenRefreshView(TokenRefreshView):
# #     # Optionally, override the default behavior
# #     pass

# from rest_framework import status, permissions
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from rest_framework import status, generics
# from django.contrib.auth import authenticate, login, logout
# from .models import Users
# from .serializers import UserSerializer, UserLoginSerializer
# from rest_framework.permissions import AllowAny

# class RegisterUser(generics.ListCreateAPIView):
    
#     # permission_classes = [AllowAny]
    
#     queryset = Users.objects.all()
#     serializer_class = UserSerializer
#     def post(self, request, *args, **kwargs):
#         username = request.data.get('username')
#         password = request.data.get('password')
#         role = request.data.get('role')
#         if Users.objects.filter(username=username).exists():
#             return Response({"error": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST)
#         user = Users.objects.create_user(username=username, role=role, password=password)
#         return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)

# class LoginUser(generics.CreateAPIView):
#     queryset = Users.objects.all()
#     serializer_class = UserLoginSerializer
#     def post(self, request, *args, **kwargs):
#         username = request.data.get('username')
#         password = request.data.get('password')
#         user = authenticate(request, username=username, password=password)
#         if user is not None:
#             login(request, user)
#             return Response({"message":"Logged in successfully","username": user.username}, status=status.HTTP_200_OK)
#         return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)

# class LogoutUser(APIView):
#     def get(self, request, *args, **kwargs):
#         username = request.user.username if request.user.is_authenticated else None
#         logout(request)
#         return Response({"message": "Logged out successfully","username":username}, status=status.HTTP_200_OK)


# # views.py

# from rest_framework import viewsets
# from django.contrib.auth.decorators import login_required
# from .models import Vehicle, AssignVehicle, CustomerVehicle, Service, ServiceRequest
# from .serializers import (
#     VehicleSerializer, AssignVehicleSerializer, CustomerVehicleSerializer,
#     ServiceSerializer, ServiceRequestSerializer
# )
# from .permissions import IsShowroomOwner, IsServiceAgent, IsCustomer, IsAdminOrReadOnly


# class VehicleViewSet(viewsets.ModelViewSet):
#     queryset = Vehicle.objects.all()
#     serializer_class = VehicleSerializer
#     permission_classes = [IsShowroomOwner | IsAdminOrReadOnly]  # Showroom owners or admins can edit

# class AssignVehicleViewSet(viewsets.ModelViewSet):
#     queryset = AssignVehicle.objects.all()
#     serializer_class = AssignVehicleSerializer
#     permission_classes = [IsServiceAgent | IsAdminOrReadOnly]  # Service agents or admins can edit

# class CustomerVehicleViewSet(viewsets.ModelViewSet):
#     queryset = CustomerVehicle.objects.all()
#     serializer_class = CustomerVehicleSerializer
#     permission_classes = [IsCustomer | IsAdminOrReadOnly]  # Customers or admins can edit

# class ServiceViewSet(viewsets.ModelViewSet):
#     queryset = Service.objects.all()
#     serializer_class = ServiceSerializer
#     permission_classes = [IsServiceAgent | IsAdminOrReadOnly]  # Service agents or admins can edit

# class ServiceRequestViewSet(viewsets.ModelViewSet):
#     queryset = ServiceRequest.objects.all()
#     serializer_class = ServiceRequestSerializer
#     permission_classes = [IsCustomer | IsAdminOrReadOnly]  # Customers or admins can edit


from rest_framework import generics, permissions, status
from rest_framework.response import Response
from django.contrib.auth import authenticate, login, logout
from django.utils import timezone
from datetime import datetime
from .models import *
from .serializers import *
from .permissions import *

class RegisterUser(generics.ListCreateAPIView):
    queryset = Users.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]  # Allow any user to register

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
    permission_classes = [permissions.AllowAny]  # Allow any user to register
    lookup_field = 'User_id' 

    # def post(self, request, *args, **kwargs):
    #     username = request.data.get('username')
    #     password = request.data.get('password')
    #     role = request.data.get('role')

    #     if Users.objects.filter(username=username).exists():
    #         return Response({"error": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST)

    #     user = Users.objects.create_user(username=username, role=role, password=password)
    #     return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
    
class LoginUser(generics.CreateAPIView):
    queryset = Users.objects.all()
    serializer_class = UserLoginSerializer
    permission_classes = [permissions.AllowAny]  # Allow any user to log in

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            # current_time = datetime.now(datetime.timezone.utc).isoformat()
            current_time = datetime.now().isoformat()
            return Response({"message": "Logged in successfully", "username": user.username,"Login_at":current_time}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)


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
    # permission_classes = [IsShowroomOwner | IsAdminOrReadOnly]


class VehicleRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Vehicle.objects.all()
    serializer_class = VehicleSerializer
    # permission_classes = [IsShowroomOwner | IsAdminOrReadOnly]

# class AssignVehicleListCreateView(generics.ListCreateAPIView):
#     queryset = AssignVehicle.objects.all()
#     serializer_class = AssignVehicleSerializer
    # permission_classes = [IsShowroomOwner | IsAdminOrReadOnly]


class AssignVehicleRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = AssignVehicle.objects.all()
    serializer_class = AssignVehicleSerializer
    # permission_classes = [IsShowroomOwner | IsAdminOrReadOnly]

class CustomerVehicleListCreateView(generics.ListCreateAPIView):
    queryset = CustomerVehicle.objects.all()
    serializer_class = CustomerVehicleSerializer
    # permission_classes = [IsCustomer | IsAdminOrReadOnly]


class CustomerVehicleRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = CustomerVehicle.objects.all()
    serializer_class = CustomerVehicleSerializer
    # permission_classes = [IsCustomer | IsAdminOrReadOnly]

class ServiceListCreateView(generics.ListCreateAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    # permission_classes = [IsServiceAgent | IsAdminOrReadOnly]


class ServiceRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    # permission_classes = [IsServiceAgent | IsAdminOrReadOnly]

class ServiceRequestListCreateView(generics.ListCreateAPIView):
    queryset = ServiceRequest.objects.all()
    serializer_class = ServiceRequestSerializer
    # permission_classes = [IsCustomer | IsAdminOrReadOnly]


class ServiceRequestRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = ServiceRequest.objects.all()
    serializer_class = ServiceRequestSerializer
    # permission_classes = [IsCustomer | IsAdminOrReadOnly]


# class UpcomingServiceListView(generics.ListAPIView):
#     queryset = CustomerVehicle.objects.all()
#     serializer_class = UpcomingServiceSerializer
#     # permission_classes = [IsServiceAgent]  # Or use a different permission class

from django.utils import timezone
from rest_framework import generics
from .models import CustomerVehicle
from .serializers import UpcomingServiceSerializer

class UpcomingServiceListView(generics.ListAPIView):
    serializer_class = UpcomingServiceSerializer

    def get_queryset(self):
        # Get the current date
        today = timezone.now().date()

        # Get the customer from query parameters
        # customer_username = self.request.query_params.get('customer', None)

        # Build the queryset
        queryset = CustomerVehicle.objects.filter(service_Due_date__gt=today)

        # if customer_username:
        #     queryset = queryset.filter(customer__username=customer_username)

        return queryset



from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from .models import AssignVehicle, Vehicle
from .serializers import AssignVehicleSerializer

# class AssignVehicleListCreateView(generics.ListCreateAPIView):
#     queryset = AssignVehicle.objects.all()
#     serializer_class = AssignVehicleSerializer



from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.template.loader import render_to_string
from rest_framework import generics, permissions, status
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import PasswordResetSerializer
from django.contrib.auth import get_user_model

User = get_user_model()

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


from django.contrib.auth.forms import SetPasswordForm
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator

User = get_user_model()

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


from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import update_session_auth_hash, get_user_model
from django.contrib.auth.forms import SetPasswordForm
from rest_framework.permissions import IsAuthenticated

User = get_user_model()

class ChangePasswordView(generics.GenericAPIView):
    
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can change their password

    def post(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            old_password = serializer.validated_data['old_password']
            new_password1 = serializer.validated_data['new_password1']

            # Check if the old password is correct
            if not user.check_password(old_password):
                return Response({"old_password": ["Old password is incorrect."]}, status=status.HTTP_400_BAD_REQUEST)

            # Use SetPasswordForm to validate new passwords
            form = SetPasswordForm(user=user, data={
                'new_password1': new_password1,
                'new_password2': serializer.validated_data['new_password2']
            })
            if form.is_valid():
                form.save()
                update_session_auth_hash(request, user)  # Keep the user logged in
                return Response({"detail": "Password has been updated successfully."}, status=status.HTTP_200_OK)
            else:
                return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from .models import AssignVehicle, Vehicle
from .serializers import AssignVehicleSerializer

class AssignVehicleListCreateView(generics.ListCreateAPIView):
    queryset = AssignVehicle.objects.all()
    serializer_class = AssignVehicleSerializer

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



# from django.db.models import Sum, F, FloatField
# from django.db.models.functions import Cast
# from django.utils import timezone
# from datetime import datetime as dt, timedelta
# from .models import AssignVehicle, Vehicle

# def generate_daily_sales_report(start_date=None, end_date=None):
#     # Default to the last 30 days if no dates are provided
#     if not start_date:
#         start_date = (timezone.now() - timedelta(days=30)).date().isoformat()
#     if not end_date:
#         end_date = timezone.now().date().isoformat()

#     # Convert start_date and end_date to date objects if they are strings
#     try:
#         if isinstance(start_date, str):
#             start_date = dt.fromisoformat(start_date).date()
#         if isinstance(end_date, str):
#             end_date = dt.fromisoformat(end_date).date()
#     except ValueError:
#         raise ValueError("Invalid date format. Dates must be in 'YYYY-MM-DD' format.")

#     # Aggregate sales data by day
#     sales_data = (AssignVehicle.objects
#                   .filter(assigned_at__date__range=[start_date, end_date])
#                   .select_related('vehicle')  # Join with Vehicle to access price
#                   .values('assigned_at__date')  # Group by date
#                   .annotate(total_quantity=Sum('quantity'))
#                   .annotate(total_revenue=Sum(Cast(F('quantity') * F('vehicle__price'), FloatField())))
#                   .order_by('assigned_at__date'))

#     # Format the data for reporting
#     report = []
#     for entry in sales_data:
#         report.append({
#             'date': entry['assigned_at__date'],
#             'total_quantity': entry['total_quantity'],
#             'total_revenue': entry['total_revenue']
#         })

#     return report


# from django.http import JsonResponse
# from django.views.decorators.http import require_GET

# @require_GET
# def sales_report_view(request):
#     # Extract date parameters from the request
#     start_date = request.GET.get('start_date')
#     end_date = request.GET.get('end_date')
    
#     # Generate the report
#     try:
#         report = generate_daily_sales_report(start_date=start_date, end_date=end_date)
#     except ValueError as e:
#         return JsonResponse({'error': str(e)}, status=400)
    
#     # Return the report as JSON
#     return JsonResponse(report, safe=False)

from django.http import JsonResponse
from django.views import View
from django.utils import timezone
from datetime import datetime as dt, timedelta
from django.db.models import Sum, F, FloatField
from django.db.models.functions import Cast
from .models import AssignVehicle

class SalesReportView(View):
    
    def get(self, request, *args, **kwargs):
        # Extract date parameters and days parameter from the request
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        days = kwargs.get('days', None)  # Extract days from the URL path
        
        # Generate the report
        try:
            report = self.generate_daily_sales_report(start_date=start_date, end_date=end_date, days=days)
        except ValueError as e:
            return JsonResponse({'error': str(e)}, status=400)
        
        # Return the report as JSON
        return JsonResponse(report, safe=False)

    def generate_daily_sales_report(self, start_date=None, end_date=None, days=None):
        # Default to the last 'days' days if no start_date is provided
        if days is not None:
            try:
                days = int(days)
            except ValueError:
                raise ValueError("Invalid value for 'days'. Must be an integer.")
            
            if days < 0:
                raise ValueError("'days' cannot be negative.")
            
            if days == 0:
                # If days is 0, use today's date for both start_date and end_date
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

        # Convert start_date and end_date to date objects if they are strings
        try:
            if isinstance(start_date, str):
                start_date = dt.fromisoformat(start_date).date()
            if isinstance(end_date, str):
                end_date = dt.fromisoformat(end_date).date()
        except ValueError:
            raise ValueError("Invalid date format. Dates must be in 'YYYY-MM-DD' format.")

        # Aggregate sales data by day
        sales_data = (AssignVehicle.objects
                      .filter(assigned_at__date__range=[start_date, end_date])
                      .select_related('vehicle')  # Join with Vehicle to access price
                      .values('assigned_at__date')  # Group by date
                      .annotate(total_quantity=Sum('quantity'))
                      .annotate(total_revenue=Sum(Cast(F('quantity') * F('vehicle__price'), FloatField())))
                      .order_by('assigned_at__date'))

        # Format the data for reporting
        report = []
        for entry in sales_data:
            report.append({
                'date': entry['assigned_at__date'],
                'total_quantity': entry['total_quantity'],
                'total_revenue': entry['total_revenue']
            })

        return report


from django.http import JsonResponse
from django.views import View
from django.shortcuts import get_object_or_404
from .models import Service, ServiceRequestt
from datetime import timedelta

from django.shortcuts import get_object_or_404
from django.utils import timezone
from datetime import timedelta
from .models import Service, ServiceRequestt
from .utils import send_service_scheduled_email

class ScheduleServicesView(View):
    def get(self, request, *args, **kwargs):
        """
        Handle GET request to schedule services for a specific ServiceRequest ID
        and return a JSON response.
        """
        service_request_id = self.kwargs.get('service_request_id')

        if not service_request_id:
            return JsonResponse({'status': 'error', 'message': 'Service request ID not provided'}, status=400)

        try:
            result = schedule_services(service_request_id)
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
        
def schedule_services(service_request_id):
    """
    Schedule services based on the FIFO principle and service type constraints
    for a specific ServiceRequest ID.
    """
    max_services_per_day = {
        'Full Service': 1,
        'Regular Service': 3,
        'Customize Service': 2
    }

    # Fetch a single ServiceRequestt instance
    request = get_object_or_404(ServiceRequestt, service_request_id=service_request_id)

    # Check if the request_at is None and handle it
    if request.request_at is None:
        return "Request date is not set for this request."

    service_type = request.service_type
    if service_type not in max_services_per_day:
        raise ValueError('Invalid service type')

    daily_limit = max_services_per_day[service_type]
    start_date = request.request_at + timedelta(days=1)
    number_of_services_to_schedule = 1  # You may set this to a different value based on your needs

    current_date = start_date
    first_service_date = None

    while number_of_services_to_schedule > 0:
        # Count the number of services already scheduled for the current date
        existing_services_count = Servicee.objects.filter(
            service_date__date=current_date.date(),
            service_type=service_type
        ).count()

        available_slots = daily_limit - existing_services_count

        if available_slots > 0:
            # If there are available slots, determine how many services we can create
            services_to_create = min(available_slots, number_of_services_to_schedule)
            
            # Create and save the necessary number of services
            services = [
                Servicee(
                    service_request_id=request,  # Use the instance correctly
                    service_date=current_date.date(),
                    service_type=service_type
                )
                for _ in range(services_to_create)
            ]
            Servicee.objects.bulk_create(services)
            
            if first_service_date is None:
                first_service_date = current_date.date()
            
            number_of_services_to_schedule -= services_to_create
        
        if number_of_services_to_schedule > 0:
            # Move to the next day if there are still services to schedule
            current_date += timedelta(days=1)

    if first_service_date:
        request.service_scheduled_date = first_service_date
        request.save()
    
    
    # send_service_scheduled_email(request)
    return "Service scheduling completed."


# from django.db.models import Count
# from django.shortcuts import get_object_or_404
# from django.http import JsonResponse
# from django.views import View
# from datetime import timedelta
# from .models import Servicee, ServiceRequestt
# from .utils import send_service_scheduled_email

# from django.db.models import Count

# max_services_per_day = {
#     'Full Service': 1,
#     'Regular Service': 3,
#     'Customize Service': 2
# }

# max_services_day = 7


# class ScheduleServicesView(View):
#     def get(self, request, *args, **kwargs):
#         """
#         Handle GET request to schedule services for a specific ServiceRequest ID
#         and return a JSON response.
#         """
#         service_request_id = self.kwargs.get('service_request_id')

#         if not service_request_id:
#             return JsonResponse({'status': 'error', 'message': 'Service request ID not provided'}, status=400)

#         try:
#             result = self.schedule_services(service_request_id)
#             response = {
#                 'status': 'success',
#                 'message': result
#             }
#             return JsonResponse(response, status=200)
#         except Exception as e:
#             response = {
#                 'status': 'error',
#                 'message': str(e)
#             }
#             return JsonResponse(response, status=500)

#     def get_scheduled_service_type_services_count(self, service_type, date):
#         """
#         Calculate how many services of a specific type are scheduled on a given date.
#         """
#         return Servicee.objects.filter(
#             service_date=date,
#             service_type=service_type
#         ).count()

#     def get_scheduled_services_count(self, date):
#         """
#         Calculate how many services are scheduled on a given date.
#         """
#         return Servicee.objects.filter(
#             service_date=date
#         ).count()

#     def schedule_services(self, service_request_id):
#         """
#         Schedule services based on the FIFO principle and service type constraints
#         for a specific ServiceRequest ID.
#         """
#         try:
#             # Fetch the ServiceRequestt instance
#             request = get_object_or_404(ServiceRequestt, service_request_id=service_request_id)
#         except Exception as e:
#             raise RuntimeError(f"Error fetching service request: {str(e)}")
        
#         # Check if the request_at is None and handle it
#         if request.request_at is None:
#             return "Request date is not set for this request."

#         # Check if services have already been scheduled
#         if Servicee.objects.filter(service_request_id=request).exists():
#             return "Services have already been scheduled for this request."

#         service_type = request.service_type
#         if service_type not in max_services_per_day:
#             raise ValueError('Invalid service type')
        
#         daily_limit = max_services_per_day[service_type]
#         start_date = request.request_at + timedelta(days=1)
#         current_date = start_date

#         while True:
#             try:
#                 # Check if we can schedule services on the current date
#                 existing_services_count_on_day = self.get_scheduled_services_count(current_date.date())
#                 existing_services_count_for_type = self.get_scheduled_service_type_services_count(service_type, current_date.date())

#                 # Define maximum constraints per day for each service type
#                 max_constraints = {
#                     'Full Service': 1,
#                     'Regular Service': 3,
#                     'Customize Service': 2
#                 }
                
#                 max_services_for_type = max_constraints.get(service_type, 0)

#                 # Check constraints for scheduling
#                 available_slots = max_services_day - existing_services_count_on_day
#                 if service_type in max_constraints:
#                     available_slots = min(available_slots, max_services_for_type - existing_services_count_for_type)

#                 if available_slots <= 0:
#                     # Move to the next day if no slots are available
#                     current_date += timedelta(days=1)
#                     continue

#                 # Calculate how many services can be scheduled today
#                 services_to_schedule_today = min(
#                     available_slots, 
#                     daily_limit - existing_services_count_for_type
#                 )
#                 services_to_schedule_today = min(services_to_schedule_today, max_services_day - existing_services_count_on_day)

#                 # If we can schedule services today
#                 if services_to_schedule_today > 0:
#                     # Create and save the necessary number of services
#                     services = [
#                         Servicee(
#                             service_request_id=request,  # Use the instance correctly
#                             service_date=current_date.date(),
#                             service_type=service_type
#                         )
#                         for _ in range(services_to_schedule_today)
#                     ]
#                     Servicee.objects.bulk_create(services)
                    
#                     # Set the first service date if not set
#                     if request.service_scheduled_date is None:
#                         request.service_scheduled_date = current_date.date()
#                         request.save()
                    
#                     # Optionally send an email notification
#                     # send_service_scheduled_email(request)

#                     return "Service scheduling completed."

#                 # Move to the next day if we couldn't schedule today
#                 current_date += timedelta(days=1)

#             except Exception as e:
#                 raise RuntimeError(f"Error during scheduling services: {str(e)}")

# class ScheduleServicesView(View):
#     def get(self, request, *args, **kwargs):
#         """
#         Handle GET request to schedule services for a specific ServiceRequest ID
#         and return a JSON response.
#         """
#         service_request_id = self.kwargs.get('service_request_id')

#         if not service_request_id:
#             return JsonResponse({'status': 'error', 'message': 'Service request ID not provided'}, status=400)

#         try:
#             result = self.schedule_services(service_request_id)
#             response = {
#                 'status': 'success',
#                 'message': result
#             }
#             return JsonResponse(response, status=200)
#         except Exception as e:
#             response = {
#                 'status': 'error',
#                 'message': str(e)
#             }
#             return JsonResponse(response, status=500)

#     def get_scheduled_service_type_services_count(self, service_type, date):
#         """
#         Calculate how many services of a specific type are scheduled on a given date.
#         """
#         return Servicee.objects.filter(
#             service_date=date,
#             service_type=service_type
#         ).count()

#     def get_scheduled_services_count(self, date):
#         """
#         Calculate how many services are scheduled on a given date.
#         """
#         return Servicee.objects.filter(
#             service_date=date
#         ).count()

#     def schedule_services(self, service_request_id):
#         """
#         Schedule services based on the FIFO principle and service type constraints
#         for a specific ServiceRequest ID.
#         """
#         # Fetch the ServiceRequestt instance
#         request = get_object_or_404(ServiceRequestt, service_request_id=service_request_id)
        
#         # Check if the request_at is None and handle it
#         if request.request_at is None:
#             return "Request date is not set for this request."

#         # Check if services have already been scheduled
#         if Servicee.objects.filter(service_request_id=request).exists():
#             return "Services have already been scheduled for this request."

#         service_type = request.service_type
#         if service_type not in max_services_per_day:
#             raise ValueError('Invalid service type')
        
#         daily_limit = max_services_per_day[service_type]
#         start_date = request.request_at + timedelta(days=1)
#         current_date = start_date

#         while True:
#             # Check if we can schedule services on the current date
#             existing_services_count_on_day = self.get_scheduled_services_count(current_date.date())
#             existing_services_count_for_type = self.get_scheduled_service_type_services_count(service_type, current_date.date())

#             # Calculate the number of services we can still schedule for today
#             available_slots = max_services_day - existing_services_count_on_day
#             if available_slots <= 0:
#                 # Move to the next day if no slots are available
#                 current_date += timedelta(days=1)
#                 continue

#             # Calculate how many services can be scheduled today
#             services_to_schedule_today = min(
#                 available_slots, 
#                 daily_limit - existing_services_count_for_type
#             )
#             services_to_schedule_today = min(services_to_schedule_today, max_services_day - existing_services_count_on_day)

#             # If we can schedule services today
#             if services_to_schedule_today > 0:
#                 # Create and save the necessary number of services
#                 services = [
#                     Servicee(
#                         service_request_id=request,  # Use the instance correctly
#                         service_date=current_date.date(),
#                         service_type=service_type
#                     )
#                     for _ in range(services_to_schedule_today)
#                 ]
#                 Servicee.objects.bulk_create(services)
                
#                 # Set the first service date if not set
#                 if request.service_scheduled_date is None:
#                     request.service_scheduled_date = current_date.date()
#                     request.save()
                
#                 # Optionally send an email notification
#                 # send_service_scheduled_email(request)

#                 return "Service scheduling completed."

#             # Move to the next day if we couldn't schedule today
#             current_date += timedelta(days=1)





class ServiceRequesttListCreateView(generics.ListCreateAPIView):
    queryset = ServiceRequestt.objects.all()
    serializer_class = ServiceRequesttSerializer
    

# def schedule_services(service_request_id):
#     """
#     Schedule services based on the FIFO principle and service type constraints
#     for a specific ServiceRequest ID.
#     """
#     max_services_per_day = {
#         'Full Service': 2,
#         'Regular Service': 6,
#         'Customize Service': 4
#     }

#     # Fetch a single ServiceRequestt instance
#     request = get_object_or_404(ServiceRequestt, service_request_id=service_request_id)

#     # Check if the request_at is None and handle it
#     if request.request_at is None:
#         return "Request date is not set for this request."

#     service_type = request.service_type
#     if service_type not in max_services_per_day:
#         raise ValueError('Invalid service type')

#     daily_limit = max_services_per_day[service_type]
#     start_date = request.request_at + timedelta(days=2)
#     number_of_services_to_schedule = 1
    
#     current_date = start_date
#     first_service_date = None

#     while number_of_services_to_schedule > 0:
#         existing_services_count = Servicee.objects.filter(
#             service_date__date=current_date.date(),
#             service_request_id=request  # Use the instance correctly
#         ).count()

#         available_slots = daily_limit - existing_services_count

#         if available_slots > 0:
#             services_to_create = min(available_slots, number_of_services_to_schedule)
#             services = [
#                 Servicee(
#                     service_request_id=request,  # Use the instance correctly
#                     service_date=current_date,
#                     service_type=service_type
#                 )
#                 for _ in range(services_to_create)
#             ]
#             Servicee.objects.bulk_create(services)
            
#             if first_service_date is None:
#                 first_service_date = current_date
            
#             number_of_services_to_schedule -= services_to_create
        
#         if number_of_services_to_schedule > 0:
#             current_date += timedelta(days=1)

#     if first_service_date:
#         request.service_scheduled_date = first_service_date
#         request.save()
    
#     return "Service scheduling completed."

# class ServiceeeListCreateView(generics.ListCreateAPIView):
#     queryset = Serviceee.objects.all()
#     serializer_class = ServiceeeSerializer


from django.http import JsonResponse
from django.utils import timezone
from .models import ServiceRequestt

def upcoming_services(request):
    now = timezone.now()
    services = ServiceRequestt.objects.filter(service_scheduled_date__gte=now).order_by('service_scheduled_date')

    # Serialize data
    services_list = list(services.values('customer', 'service_scheduled_date', 'service_request_id'))

    return JsonResponse({'Upcoming_Services': services_list})


from django.http import JsonResponse
from django.utils import timezone
from .models import Servicee

def service_history(request):
    # Filter completed services
    completed_services = Servicee.objects.filter(status='Completed').order_by('service_date')
    
    # Serialize data
    services_list = list(completed_services.values(
        'service_id', 'service_request_id', 'service_date', 'service_type', 'description', 'status', 'next_service_date', 'performed_by__username'
    ))
    
    return JsonResponse({'service_history': services_list})

