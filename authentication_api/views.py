from authentication_api.models import ForgetPassword, Book
from authentication_api.serializers import UserSerializer
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import NotFound
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_200_OK,
    HTTP_404_NOT_FOUND,
)
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.core.mail import EmailMessage
from django.db import IntegrityError
from django.template.loader import render_to_string
from rest_framework.permissions import AllowAny
from django.utils.crypto import get_random_string


class RegistrationAPIView(APIView):
    """
    API View to register a new user.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        """
        Create a new user account by accepting user details

        Parameters:
        request (Request): The incoming request object

        Returns:
        Response: JSON response containing the user's details and
                  the authentication token if successful.
                  Error response if request is invalid or
                  user with the same email already exists.
        """
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "status": True,
                "message": "User created successfully",
                "data": None,
            }, status=HTTP_201_CREATED)
        else:
            return Response({
                "status": False,
                "errors": serializer.errors,
                "data": None
            }, status=HTTP_400_BAD_REQUEST)


class EmailLoginAPIView(APIView):
    """
    API View for user email-based login.
    """

    def post(self, request):
        """
        Authenticate a user and generate a new authentication token by
        accepting user email and password.

        Parameters:
        request (Request): The incoming request object

        Returns:
        Response: JSON response containing the authentication token
            if successful.
            Error response if email or password is missing or invalid.
        """
        email = request.data.get("email")
        password = request.data.get("password")
        if email and password:
            users = User.objects.filter(email=email)
            if not users.exists():
                return Response({
                    "status": False,
                    "message": "User does not exist",
                    "data": None
                }, status=HTTP_404_NOT_FOUND,)

            user = users.first()
            if user.check_password(password):
                if user.is_active:
                    # Delete the old auth token
                    token = Token.objects.filter(user=user).first()
                    if token:
                        token.delete()

                    # Generate auth token and return it in response
                    token = Token.objects.create(user=user)

                    return Response({
                        "status": True,
                        "message": "User Login successfully",
                        "data": {"token": token.key},
                    }, status=HTTP_200_OK)
                else:
                    return Response({
                        "status": False,
                        "message": "User account is not active",
                        "data": None,
                    }, status=HTTP_401_UNAUTHORIZED)
            else:
                return Response({
                    "status": False,
                    "message": "Invalid email or password",
                    "data": None,
                }, status=HTTP_401_UNAUTHORIZED)
        else:
            return Response({
                    "status": False,
                    "message": "Missing email or password field",
                    "data": None,
                }, status=HTTP_401_UNAUTHORIZED)


class ForgetPasswordAPIView(APIView):
    """
    API View for user password reset.
    """

    def post(self, request):
        """
        This code defines an API view for resetting user password.
        When a POST request is received with an email address,
        it generates a random OTP, sends it to the user's email address,
        and saves the OTP in the ForgetPassword model.
        If the email address is not provided or the user is inactive,
        it returns an appropriate error message.
        """
        email = request.data.get("email")

        if email:
            users = User.objects.filter(email=email)
            if not users.exists():
                return Response({
                    "status": False,
                    "message": "User does not exist",
                    "data": None
                }, status=HTTP_404_NOT_FOUND)

            user = users.first()
            if user.is_active:

                # Delete any existing forget password entry
                forget_password = ForgetPassword.objects.filter(user=user)
                if forget_password:
                    forget_password.delete()

                # Generate random OTP
                otp = get_random_string(length=6, allowed_chars="0123456789")

                # Send email with the authtoken and OTP to the user
                email_subject = f"OTP for the {user}"
                email_body = render_to_string(
                    "registration_email.txt", {"user": user, "otp": otp}
                )
                email = EmailMessage(
                    email_subject,
                    email_body,
                    to=[user.email],
                )
                email.send()

                # Save OTP to forget password entry
                forget_password = ForgetPassword(user=user, otp=otp)
                forget_password.save()

                return Response({
                    "status": True,
                    "message": "OTP sent successfully",
                    "data": None,
                }, status=HTTP_200_OK)
            else:
                return Response({
                    "status": False,
                    "message": "User is not active",
                    "data": None,
                }, status=HTTP_400_BAD_REQUEST)

        return Response({
            "status": False,
            "message": "Missing required fields",
            "data": None
        }, status=HTTP_400_BAD_REQUEST)


class UserVerifyOtpView(APIView):
    """
    API View for verifying user OTP during password reset.
    """

    def post(self, request):
        """
        Verifies the OTP provided by the user for password reset.

        Parameters:
        request (HttpRequest): The HTTP request object containing the OTP.

        Returns:
        response (HttpResponse): A JSON response containing the status of
                OTP verification and a new auth token if verification is successful.
        """
        otp = request.data.get("otp")

        # Check if OTP is present in request data, if not then return an error response
        if not otp:
            return Response({
                "status": False,
                "message": "Missing required fields",
                "data": None,
            }, status=HTTP_400_BAD_REQUEST)

        # Fetch user by OTP
        try:
            # Get the forget password entry with the provided OTP
            forget_password = ForgetPassword.objects.get(otp=otp)
        except ForgetPassword.DoesNotExist:
            # If no forget password entry with the provided OTP is found, return an error response
            raise NotFound({
                "status": False,
                "message": "OTP Verification failed",
                "data": None,
            })

        # Get the user associated with the forget password entry
        user = forget_password.user

        # Delete the old auth token
        token = Token.objects.filter(user=user).first()
        if token:
            token.delete()

        # Generate a new auth token for the user
        token = Token.objects.create(user=user)

        # Return success response with the new auth token
        return Response({
            "status": True,
            "message": "OTP is Verified Successfully.",
            "data": {"token": token.key},
        }, status=HTTP_200_OK)


class UpdatePasswordAPIView(APIView):
    """
    API View for updating user password.
    """

    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        """
        Update the user's password and generate a new authentication token.

        Parameters:
        request (Request): The incoming request object.

        Returns:
        Response: JSON response containing the new authentication token
            if the password is updated successfully.
            Error response if the new password is missing or invalid.
        """

        new_password = request.data.get("new_password")

        if not new_password:
            return Response({
                "status": False,
                "message": "Email and new_password required fields",
                "data": None,
            }, status=HTTP_400_BAD_REQUEST)

        user = request.user

        # Update user's password
        user.password = make_password(new_password)
        user.save()

        # Delete the old auth token
        token = Token.objects.filter(user=user).first()
        if token:
            token.delete()

        # Generate and set new auth token for the user
        new_token = Token.objects.create(user=user)

        return Response({
            "status": True,
            "message": "Password updated successfully",
            "data": {"token": new_token.key},
        }, status=HTTP_200_OK)


class UpdateUsernameAPIView(APIView):
    """
    API View for updating the username of a user.
    """

    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def put(self, request):
        """
        Update the username of the authenticated user.

        Required request data:
        {
            "new_username": <string>
        }

        Returns:
        - HTTP 200 OK: username updated successfully
        - HTTP 400 BAD REQUEST: missing required fields or username already exists
        """
        new_username = request.data.get("new_username")

        if not new_username:
            return Response({
                "status": False,
                "message": "Missing required fields",
                "data": "email and new_username are required",
            }, status=HTTP_400_BAD_REQUEST)

        user = request.user

        user.username = new_username
        try:
            user.save()
        except IntegrityError:
            return Response({
                "status": False,
                "message": "Username already exists",
                "data": None,
            }, status=HTTP_400_BAD_REQUEST)

        return Response({
            "status": True,
            "message": "Username updated successfully",
            "data": None,
        }, status=HTTP_200_OK)


class DeleteUserAPIView(APIView):
    """
    API View for deleting a user.

    Only authenticated users can delete their own account.

    Returns:
        A JSON response with the following fields:
            - status (bool): True if the user was deleted successfully, False otherwise
            - message (str): A message indicating the result of the operation
            - data: None
    """

    def delete(self, request):

        user = request.user
        user.delete()

        return Response({
            "status": True,
            "message": "User deleted successfully",
            "data": None,
        }, status=HTTP_200_OK)


class BookViewAPI(APIView):
    """
    API View for creating a new book for the user.

    Authentication: Token authentication is required.
    Permissions: The user must be authenticated.

    POST request:
        Required fields:
            - book_name: str
            - book_author: str
            - book_price: decimal

        Returns:
            - status: bool - True if the book was created successfully, False otherwise.
            - message: str - A message indicating whether the operation was successful.
            - data: dict - A dictionary containing the following fields:
                - id: int - The ID of the created book.
                - name: str - The name of the created book.
                - author: str - The author of the created book.
                - price: decimal - The price of the created book.
    """

    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        book_name = request.data.get("book_name")
        book_author = request.data.get("book_author")
        book_price = request.data.get("book_price")

        if not (book_name and book_author and book_price):
            return Response({
                "status": False,
                "message": "Missing required fields",
                "data": None,
            }, status=HTTP_400_BAD_REQUEST)

        user = request.user

        book = Book.objects.create(
            user=user, name=book_name, author=book_author, price=book_price
        )

        return Response({
            "status": True,
            "message": "Book created successfully",
            "data": {
                "id": book.id,
                "name": book.name,
                "author": book.author,
                "price": book.price,
            },
        }, status=HTTP_201_CREATED)


class DashboardAPIView(APIView):
    """
    API for showing the user books.
    """

    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        GET request to retrieve all books created by the user.
        Returns a JSON response with the book data.
        """
        user = request.user
        books = Book.objects.filter(user=user).values("name", "author", "price")

        return Response({
            "status": True,
            "message": "All books retrieved successfully",
            "data": books,
        }, status=HTTP_200_OK)
