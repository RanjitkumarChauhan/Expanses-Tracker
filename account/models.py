from django.db import models

from authentication.models import Users
from master.models import BaseClass
from PIL import Image

# Create your models here.
class IncomeModel(BaseClass):
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    date = models.DateField()
    amount = models.DecimalField(default=0,decimal_places=2,max_digits=10)

    def __str__(self):
        return f"IncomeModelID:{self.pk}"

class Category(BaseClass):
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class Expenses(BaseClass):
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    category_id=models.ForeignKey(Category,on_delete=models.CASCADE)
    date = models.DateField()
    amount = models.DecimalField(default=0,decimal_places=2,max_digits=10)
    description = models.TextField(default="--")


    def __str__(self):
        return f"ExpensesID:{self.pk}"

class ImgSlider(BaseClass):
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    photo = models.ImageField(upload_to='images/')

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

        img = Image.open(self.photo.path)
        max_size = (1000, 800)
        img.thumbnail(max_size)
        img.save(self.photo.path)

    def __str__(self):
        return f"ImgSliderID:{self.pk}"