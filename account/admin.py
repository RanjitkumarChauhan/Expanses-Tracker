from django.contrib import admin
from .models import IncomeModel,Category,Expenses,ImgSlider

# Register your models here.
admin.site.register(IncomeModel)
admin.site.register(Category)
admin.site.register(Expenses)
admin.site.register(ImgSlider)