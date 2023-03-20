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
    HTTP_200_OK,)
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core.mail import EmailMessage
from django.db import IntegrityError
from django.template.loader import render_to_string
from rest_framework.permissions import AllowAny
from django.utils.crypto import get_random_string


# Helper function to retrieve user object by email
def get_user_by_email(self, email):
    UserModel = get_user_model()
    try:
        return UserModel.objects.get(email=email)
    except UserModel.DoesNotExist:
        raise NotFound({'status': False,
                        'message': f'This User {email} is not exist',
                        'data': None})


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
            content = {
                'status': True,
                'message': 'User created successfully',
                'data': None
                }
            return Response(content, status=HTTP_201_CREATED)
        else:
            content = {
                    'status': False,
                    'errors': serializer.errors,
                    'data': None
                    }
            return Response(content, status=HTTP_400_BAD_REQUEST)


class EmailLoginAPIView(APIView):
    """
    API View for user email-based login.
    """

    def post(self, request):
        """
        Authenticate a user and generate a new authentication token by
        accepting user email and password

        Parameters:
        request (Request): The incoming request object

        Returns:
        Response: JSON response containing the authentication token
            if successful.
            Error response if email or password is missing or invalid.
        """
        email = request.data.get('email')
        password = request.data.get('password')
        if email and password:
            user = get_user_by_email(self, email=email)
            if user.check_password(password):
                if user.is_active:

                    # Delete the old auth token
                    token = Token.objects.filter(user=user).first()
                    if token:
                        token.delete()

                    # Generate auth token and return it in response
                    token = Token.objects.create(user=user)
                    content = {
                        'status': True,
                        'message': 'User Login successfully',
                        'data': {'token': token.key}
                        }

                    return Response(content, status=HTTP_200_OK)
                else:
                    content = {
                        'status': False,
                        'message': 'User account is not active',
                        'data': None
                        }
                    return Response(content, status=HTTP_401_UNAUTHORIZED)
            else:
                content = {
                    'status': False,
                    'message': 'Invalid password',
                    'data': None
                    }
                return Response(content, status=HTTP_401_UNAUTHORIZED)
        content = {
            'status': False,
            'message': 'Missing Required Field.',
            'data': 'Email and password required fields'
            }
        return Response(content, status=HTTP_401_UNAUTHORIZED)


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
        email = request.data.get('email')

        if email:
            user = get_user_by_email(self, email=email)
            if user.is_active:

                # Delete any existing forget password entry
                forget_password = ForgetPassword.objects.filter(user=user)
                if forget_password:
                    forget_password.delete()

                # Generate random OTP
                otp = get_random_string(length=6, allowed_chars='0123456789')

                # Send email with the authtoken and OTP to the user
                email_subject = f'OTP for the {user}'
                email_body = render_to_string('registration_email.txt', {
                    'user': user,
                    'otp': otp
                })
                email = EmailMessage(
                    email_subject,
                    email_body,
                    to=[user.email],
                )
                email.send()

                # Save OTP to forget password entry
                forget_password = ForgetPassword(user=user, otp=otp)
                forget_password.save()

                content = {
                    'status': True,
                    'message': 'OTP sent successfully',
                    'data': None
                }
                return Response(content, status=HTTP_200_OK)
            else:
                content = {
                    'status': False,
                    'message': 'User is not active',
                    'data': None
                }
                return Response(content, status=HTTP_400_BAD_REQUEST)

        content = {
            'status': False,
            'message': 'Missing required fields',
            'data': 'email is required'
        }
        return Response(content, status=HTTP_400_BAD_REQUEST)


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
        otp = request.data.get('otp')

        # Check if OTP is present in request data, if not then return an error response
        if not otp:
            content = {
                'status': False,
                'message': 'Missing required fields',
                'data': 'OTP is required'
                }
            return Response(content, status=HTTP_400_BAD_REQUEST)

        # Fetch user by OTP
        try:
            # Get the forget password entry with the provided OTP
            forget_password = ForgetPassword.objects.get(otp=otp)
        except ForgetPassword.DoesNotExist:
            # If no forget password entry with the provided OTP is found, return an error response
            content = {
                'status': False,
                'message': 'OTP Verification failed',
                'data': None
                }
            raise NotFound(content)

        # Get the user associated with the forget password entry
        user = forget_password.user

        # Delete the old auth token, if present
        token = Token.objects.filter(user=user).first()
        if token:
            token.delete()

        # Generate a new auth token for the user
        token = Token.objects.create(user=user)

        # Return success response with the new auth token
        content = {
            'status': True,
            'message': 'OTP is Verified Successfully.',
            'data': {'token': token.key}
            }
        return Response(content, status=HTTP_200_OK)


class UpdatePasswordAPIView(APIView):
    """
    API View for updating user password.
    """
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        new_password = request.data.get('new_password')

        if not new_password:
            content = {'status': False,
                       'message': 'Email and new_password required fields',
                       'data': None}
            return Response(content, status=HTTP_400_BAD_REQUEST)

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

        content = {'status': True,
                   'message': 'Password updated successfully',
                   'data': {'token': new_token.key}}
        return Response(content, status=HTTP_200_OK)


class UpdateUsernameAPIView(APIView):
    """
    API View for updating the username of a user.
    """
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def put(self, request):
        new_username = request.data.get('new_username')

        if not new_username:
            content = {'status': False,
                       'message': 'Missing required fields',
                       'data': 'email and new_username are required'}
            return Response(content, status=HTTP_400_BAD_REQUEST)

        user = request.user

        user.username = new_username
        try:
            user.save()
        except IntegrityError:
            content = {'status': False,
                       'message': 'Username already exists',
                       'data': None}
            return Response(content, status=HTTP_400_BAD_REQUEST)

        content = {'status': True,
                   'message': 'Username updated successfully',
                   'data': None}
        return Response(content, status=HTTP_200_OK)


class DeleteUserAPIView(APIView):
    """
    API View for deleting a user.
    """
    def delete(self, request):

        user = request.user
        user.delete()

        content = {'status': True,
                   'message': 'User deleted successfully',
                   'data': None}
        return Response(content, status=HTTP_200_OK)


class BookViewAPI(APIView):
    """
    API View for creating a new book for the user.
    """
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        book_name = request.data.get('book_name')
        book_author = request.data.get('book_author')
        book_price = request.data.get('book_price')

        if not (book_name and book_author and book_price):
            content = {
                'status': False,
                'message': 'Missing required fields',
                'data': 'book_name, book_author, and book_price are required'
                }
            return Response(content, status=HTTP_400_BAD_REQUEST)

        user = request.user

        book = Book.objects.create(
            user=user,
            name=book_name,
            author=book_author,
            price=book_price
            )

        content = {'status': True,
                   'message': 'Book created successfully',
                   'data': {
                       'id': book.id,
                       'name': book.name,
                       'author': book.author,
                       'price': book.price
                   }}
        return Response(content, status=HTTP_201_CREATED)


class DashboardAPIView(APIView):
    """
    API for showing the user books.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        print(user)
        books = Book.objects.filter(user=user)

        book_data = []
        for book in books:
            book_data.append({
                'name': book.name,
                'author': book.author,
                'price': book.price,
            })

        content = {'status': True,
                   'message': 'All books retrieved successfully',
                   'data': book_data}
        return Response(content, status=HTTP_200_OK)
