from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.

class MyUser(AbstractUser):
    phone_number = models.CharField(('number_phone'),max_length=15,blank=True)
    birdth_day = models.DateField(('birdth_day'),null=True,blank=True)
    sex = models.CharField(('sex'),max_length=15,blank=True)

    def get_email(self):
        return self.email
