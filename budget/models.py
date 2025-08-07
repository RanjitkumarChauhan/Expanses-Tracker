from django.db import models

from authentication.models import Users


# Create your models here.

class Budget(models.Model):
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    amount = models.BigIntegerField()
