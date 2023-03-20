from django.db import models
from django.contrib.auth.models import User


class ForgetPassword(models.Model):
    """
    Model representing a forget password request.

    Attributes:
        user (ForeignKey): A reference to the User who requested the forget password.
        otp (CharField): The OTP code generated for the forget password request.
        created_at (DateTimeField): The date and time when the forget password request was created.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"OTP {self.otp} for {self.user.email}"


class Book(models.Model):
    """
    Model representing a book.

    Attributes:
        name (CharField): The name of the book.
        author (CharField): The name of the book's author.
        price (DecimalField): The price of the book.
        created_at (DateTimeField): The date and time when the book was created.
        user (ForeignKey): A reference to the User who created the book.
    """
    name = models.CharField(max_length=255)
    author = models.CharField(max_length=255)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.name
