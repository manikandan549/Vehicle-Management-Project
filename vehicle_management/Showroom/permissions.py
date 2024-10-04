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


