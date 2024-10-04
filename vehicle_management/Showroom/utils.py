# utils.py
from django.core.mail import send_mail
from django.utils.html import strip_tags
from django.template.loader import render_to_string
from .models import *

# def send_service_scheduled_email(service_requestt):
#     subject = 'Your Service Scheduling is Completed'
#     message = (
#         f"Hello {service_requestt.customer_vehicle.customer.username},\n\n"
#         f"Your service request has been successfully scheduled.\n"
#         f"Service Type: {service_requestt.service_type}\n"
#         f"First Scheduled Service Date: {service_requestt.service_scheduled_date}\n"
#         f"Vehicle Details: {service_requestt.customer_vehicle.vehicle_details}\n\n"
#         f"Thank you for scheduling your service with us!"
#     )
#     recipient_list = [service_requestt.customer_vehicle.customer.email]

#     send_mail(subject, message, 'kmanikandan549@gmail.com', recipient_list)

# utils.py
from django.core.mail import send_mail
from .models import *

# def send_service_scheduled_email(service_request_id):
#     """
#     Send an email notification about the service scheduling completion.
#     """
#     if not service_request_id:
#         raise ValueError("Invalid service request or customer vehicle")

#     customer = service_request_id.customer
#     customer = customer_vehicle.customer
#     vehicle_details = service_request_id.customer_vehicle
#     # customer_email= User.objects.get(vehicle=vehicle_name)

#     subject = 'Your Service Scheduling is Completed'
#     message = (
#         f"Hello {customer},\n\n"
#         f"Your service request has been successfully scheduled.\n"
#         f"Service Type: {service_request_id.service_type}\n"
#         f"First Scheduled Service Date: {service_request_id.service_scheduled_date}\n"
#         f"Vehicle Details: {vehicle_details}\n\n"
#         f"Thank you for scheduling your service with us!"
#     )
#     recipient_list = [customer.email]

#     send_mail(subject, message, 'kmanikandan549@gmail.com', recipient_list)

# utils.py
from django.core.mail import send_mail

def send_service_scheduled_email(service_request_id):
    """
    Send an email notification about the service scheduling completion.
    """
    if not service_request_id or not service_request_id.customer_vehicle:
        raise ValueError("Invalid service request or customer vehicle")

    customer_vehicle = service_request_id.customer_vehicle
    customer = customer_vehicle.customer  # User object
    vehicle_details = customer_vehicle.vehicle_details

    subject = 'Your Service Scheduling is Completed'
    message = (
        f"Hello {customer.username},\n\n"
        f"Your service request has been successfully scheduled.\n"
        f"Service Type: {service_request_id.service_type}\n"
        f"First Scheduled Service Date: {service_request_id.service_scheduled_date}\n"
        f"Vehicle Details: {vehicle_details}\n\n"
        f"Thank you for scheduling your service with us!"
    )
    recipient_list = [customer.email]  # Access the email from the User model

    send_mail(subject, message, 'your-email@example.com', recipient_list)
