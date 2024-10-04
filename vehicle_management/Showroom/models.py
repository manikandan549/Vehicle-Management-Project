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

