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

    path('assign-vehicle/', AssignVehicleListCreateView.as_view(), name='assign-vehicle-list-create'),
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

