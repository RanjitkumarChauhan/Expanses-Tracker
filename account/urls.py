from django.urls import path

from budget.views import budget_view
from .views import *
from django.conf import settings
from django.conf.urls.static import static
urlpatterns = [
    path('register_super_user/', register_super_user, name='register_super_user'),
    path('dashboard_view/', dashboard_view, name='dashboard_view'),
    path('members_view/', members_view, name='members_view'),
    path('images/', images_view, name='images'),
    path('profile_view/', profile_view, name='profile_view'),
    path('forgot/password/', forgot_password_view, name='forgot_password_view'),
    path('reset/password/<uid>/<token>/', reset_password_view, name='reset-password'),
    path('otp_varification_view/', otp_varification_view, name='otp_varification_view'),
    path('logout/',logout,name='logout'),
    path('',login_view,name='login_view'),
    path('update_member_view/<int:id>',update_member_view,name='update_member_view'),
    path('delete_member_view/<int:id>',delete_member_view,name='delete_member_view'),
    path('income_view/',income_view,name='income_view'),
    path('expenses_view/',expenses_view,name='expenses_view'),
    path('expense_date_filter/',expense_date_filter,name='expense_date_filter'),
    path('income_date_filter/',income_date_filter,name='income_date_filter'),
    path('update_income_view/<int:id>', update_income_view, name='update_income_view'),
    path('delete_income_view/<int:id>', delete_income_view, name='delete_income_view'),
    path('update_expense_view/<int:id>', update_expense_view, name='update_expense_view'),
    path('delete_expense_view/<int:id>', delete_expense_view, name='delete_expense_view'),
    path('income_report/',download_income_report,name='download_income_report'),
    path('expense_report/',download_expense_report,name='download_expense_report'),
    path('get_record_via_filter/<int:category_id>',get_record_via_filter,name='get_record_via_filter'),
    path('delete_img/<int:id>',delete_image,name='delete_image'),
    path('budget/',budget_view, name='budget-page')
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
