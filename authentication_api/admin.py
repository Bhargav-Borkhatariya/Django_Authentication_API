from django.contrib import admin
from authentication_api.models import ForgetPassword, Book

admin.site.register((ForgetPassword, Book))
