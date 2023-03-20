from django.urls import path
from authentication_api.views import (
    RegistrationAPIView,
    EmailLoginAPIView,
    ForgetPasswordAPIView,
    UserVerifyOtpView,
    UpdatePasswordAPIView,
    UpdateUsernameAPIView,
    DeleteUserAPIView,
    BookViewAPI,
    DashboardAPIView,
)

urlpatterns = [
    # Registration API endpoint
    path("register/",
         RegistrationAPIView.as_view(),
         name="register"),

    # Email Login API endpoint
    path("email-login/",
         EmailLoginAPIView.as_view(),
         name="email-login"),

    # Forget Password API endpoint
    path("forget-password/",
         ForgetPasswordAPIView.as_view(),
         name="forget-password"),

    # User Verify OTP API endpoint
    path("verify-otp/",
         UserVerifyOtpView.as_view(),
         name="verify-otp"),

    # Update Password API endpoint
    path("update-password/",
         UpdatePasswordAPIView.as_view(),
         name="forget-password"),

    # Update Username API endpoint
    path("update_username/",
         UpdateUsernameAPIView.as_view(),
         name="update_username"),

    # Delete User API endpoint
    path("delete_user/",
         DeleteUserAPIView.as_view(),
         name="delete_user"),

    # User Book API endpoint
    path("user_book/",
         BookViewAPI.as_view(),
         name="user_book"),

    # User Dashboard API endpoint
    path("user_dashboard/",
         DashboardAPIView.as_view(),
         name="user_dashboard")
]
