import datetime
from functools import wraps

import openpyxl
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail
from django.db.models import Sum
from django.http import HttpResponse, HttpResponseNotAllowed
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.http import urlsafe_base64_decode

from authentication.forms import MembersForm
from authentication.models import Users
from budget.models import Budget
from master.utils.ME_DATETIME.me_time import DateTimeInformation
from master.utils.ME_FORMAT.format_amount import format_amount
from master.utils.ME_UNIQUE.generate_otp import generate_otp
from master.utils.ME_UNIQUE.generate_password import generate_password
from .models import Category, Expenses, ImgSlider, IncomeModel
from .utils import send_forgot_password_email_link, send_forgot_password_mail

datetimeinfo = DateTimeInformation()
start_date_of_month = datetimeinfo.get_startdate_of_month()
current_date_of_month = datetimeinfo.get_current_date()


def login_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if 'email' not in request.session:
            messages.warning(request, "You are not logged in yet.")
            return redirect('login_view')
        return view_func(request, *args, **kwargs)

    return _wrapped_view


def role_required(role):
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped_view(request, *args, **kwargs):
            user = Users.objects.get(email=request.session['email'])
            if role == 'superuser' and not user.is_superuser:
                messages.warning(request, "Only superusers can access this page.")
                return redirect('dashboard_view')
            elif role == 'member' and user.is_superuser:
                messages.warning(request, "Superusers cannot access member-only pages.")
                return redirect('dashboard_view')
            return view_func(request, *args, **kwargs)

        return _wrapped_view

    return decorator


def register_super_user(request):
    if request.method == "POST":
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        phone = request.POST['phone']
        email = request.POST['email']
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        if password != confirm_password:
            messages.warning(request, 'Passwords must match.')
            return redirect('register_super_user')

        if Users.objects.filter(email=email).exists():
            messages.warning(request, "Email already taken!")
            return redirect('register_super_user')

        try:
            Users.objects.create_superuser(
                first_name=first_name,
                last_name=last_name,
                email=email,
                phone=phone,
                password=password
            )
            messages.success(request, "Superuser registered successfully!")
            return redirect('login_view')
        except Exception as e:
            messages.warning(request, f"Something went wrong: {e}")
            return redirect('register_super_user')

    return render(request, "register.html")


@login_required
def dashboard_view(request):
    user = Users.objects.get(email=request.session['email'])
    images = ImgSlider.objects.filter(user=user if user.is_superuser else user.created_by)
    unique_category_names = Category.objects.filter(
        expenses__user__in=Users.objects.filter(created_by=user if user.is_superuser else user.created_by)
    ).values_list('id', 'name').distinct()
    context = {
        'user': user,
        'unique_category_names': unique_category_names,
        'images': images
    }
    return render(request, 'dashboard.html', context)


@role_required('superuser')
def images_view(request):
    user = Users.objects.get(email=request.session['email'])
    images = ImgSlider.objects.filter(user=user)
    if request.method == 'POST':
        if len(images) >= 5:
            messages.warning(request, 'Only 5 images can be set in slider!')
            return redirect('images')
        image_file = request.FILES.get('image')
        if image_file:
            img_slider = ImgSlider(user=user, photo=image_file)
            img_slider.save()
            messages.success(request, 'Image saved successfully.')
            return redirect('images')
        else:
            messages.warning(request, 'Select Image First.')
            return redirect('images')
    context = {
        'user': user,
        'images': images
    }
    return render(request, 'images.html', context)


@role_required('superuser')
def delete_image(request, id):
    try:
        img_instance = ImgSlider.objects.get(id=id)
        img_instance.delete()
        messages.success(request, 'Image Deleted Successfully.')
    except ImgSlider.DoesNotExist:
        messages.warning(request, 'Image does not exist.')
    except Exception as e:
        messages.warning(request, f'Something went wrong: {e}')
    return redirect('dashboard_view')


@role_required('superuser')
def get_record_via_filter(request, category_id):
    user = Users.objects.get(email=request.session['email'])
    superuser = user if user.is_superuser else user.created_by

    if user.is_superuser:
        getmembers = list(Users.objects.filter(created_by=superuser))
        if superuser not in getmembers:
            getmembers.append(superuser)
    else:
        getmembers = [user]
    ExpensesRecord = []
    for member in getmembers:
        getExpense = Expenses.objects.filter(user=member, category_id=category_id).filter(
            date__range=[datetimeinfo.convert_date_format(start_date_of_month),
                         datetimeinfo.convert_date_format(current_date_of_month)])
        if getExpense.exists():
            ExpensesRecord.append(getExpense)
    return redirect('dashboard_view')


@role_required('superuser')
def members_view(request):
    user = Users.objects.get(email=request.session['email'])
    form = MembersForm()
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        is_active = bool(request.POST.get('is_active'))

        if Users.objects.filter(email=email).exists():
            messages.warning(request, 'Email already taken!')
            return redirect('members_view')

        if Users.objects.filter(phone=phone).exists():
            messages.warning(request, 'Phone already registered!')
            return redirect('members_view')
        try:
            password = generate_password(6)
            new_user = Users.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                email=email,
                phone=phone,
                password=password,
                is_active=is_active,
                created_by=user
            )
            messages.success(request, 'Member added successfully!')
            send_forgot_password_mail(new_user, password)
            return redirect('members_view')
        except Exception as e:
            messages.error(request, f'Error adding member: {str(e)}')
    members = Users.objects.filter(created_by=user)
    context = {
        'form': form,
        'members': members,
        'user': user
    }
    return render(request, 'members.html', context)


@login_required
def profile_view(request):
    user = Users.objects.get(email=request.session['email'])
    superuser = user if user.is_superuser else user.created_by

    if user.is_superuser:
        getmembers = list(Users.objects.filter(created_by=superuser))
        if superuser not in getmembers:
            getmembers.append(superuser)
    else:
        getmembers = [user]
    total_income = 0
    total_expense = 0

    for member in getmembers:
        get_income = IncomeModel.objects.filter(user=member).filter(
            date__range=[
                datetimeinfo.convert_date_format(start_date_of_month),
                datetimeinfo.convert_date_format(current_date_of_month)
            ]
        )
        total_income += get_income.aggregate(total_amount=Sum('amount'))['total_amount'] or 0

        get_expense = Expenses.objects.filter(user=member).filter(
            date__range=[
                datetimeinfo.convert_date_format(start_date_of_month),
                datetimeinfo.convert_date_format(current_date_of_month)
            ]
        )
        total_expense += get_expense.aggregate(total_amount=Sum('amount'))['total_amount'] or 0

    remaining_amount = total_income - total_expense

    budget = Budget.objects.filter(user=superuser).first()
    budget_amount = budget.amount if budget else 0
    remaining_budget = budget_amount - total_expense if budget_amount else 0

    context = {
        'start_date_of_month': start_date_of_month,
        'current_date_of_month': current_date_of_month,
        'total_income': format_amount(total_income),
        'total_expense': format_amount(total_expense),
        'remaining_amount': format_amount(remaining_amount),
        'budget_amount': format_amount(budget_amount),
        'remaining_budget': format_amount(remaining_budget),
        'user': user
    }
    return render(request, 'profile.html', context)


def forgot_password_view(request):
    if request.method == "POST":
        email = request.POST.get('email')

        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            messages.warning(request, 'Email not registered.')
            return render(request, 'forgot_password.html')

        is_sent = send_forgot_password_email_link(request, user)
        if not is_sent:
            messages.success(request, "Something went wrong, try again later.")
            return render(request, 'forgot_password.html')

        messages.success(request, "Verification code sent to registered email.")
    return render(request, 'forgot_password.html')


def reset_password_view(request, uid, token):
    is_valid_link = False
    try:
        uid = urlsafe_base64_decode(uid).decode()
        user = Users.objects.get(id=uid)
    except Exception:
        messages.warning(request, "User miss matched.")
        return render(request, 'login.html')

    if not default_token_generator.check_token(user, token):
        messages.warning(request, "Token verification failed.")
        return render(request, 'login.html')

    is_valid_link = True

    if request.method == "POST":
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        if password != confirm_password:
            messages.warning(request, 'Password must match.')
            return render(request, 'reset_password.html')

        user.set_password(password)
        user.save()
        messages.success(request, 'Password reset success.')

    context = {'validlink': is_valid_link}
    return render(request, 'reset_password.html', context)


def otp_varification_view(request):
    if request.method == 'POST':
        email = request.POST['email']
        otp = request.POST['otp']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            messages.info(request, 'User Does Not Exist')
            return redirect('login_view')
        if otp == user.otp:
            if password == confirm_password:
                user.set_password(password)
                user.otp = None
                user.save()
                messages.success(request, 'Password Changed Successfully')
                return redirect('login_view')
            else:
                messages.warning(request, 'Passwords do not match!')
        else:
            new_otp = generate_otp()
            user.otp = new_otp
            user.save()
            subject = 'Forgot Password OTP'
            message = f"""
            Dear {user.first_name} {user.last_name},
            New OTP: {new_otp}
            Thank you,
            Miscellaneous Expenses Team
            """
            send_mail(subject, message, settings.EMAIL_HOST_USER, [email])
            messages.warning(request, f"New OTP sent to {email}!")
        return render(request, 'otp_varification.html', {'email': email})
    return redirect('login_view')


@login_required
def logout(request):
    request.session.clear()
    messages.success(request, 'Logged Out Successfully')
    return redirect('login_view')


def login_view(request):
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['password']
        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            messages.warning(request, "User not registered!")
            return redirect('login_view')
        if not user.is_active:
            messages.warning(request, "Account is deactivated. Contact your admin!")
            return redirect('login_view')
        if user.check_password(password):
            request.session['email'] = user.email
            request.session['user_id'] = user.id
            request.session['first_name'] = user.first_name
            request.session['last_name'] = user.last_name
            request.session['phone'] = user.phone
            messages.success(request, 'Login Successful!')
            return redirect('dashboard_view')
        else:
            messages.warning(request, "Invalid Password or Email!")
            return redirect('login_view')
    elif 'email' in request.session:
        return redirect('dashboard_view')
    return render(request, 'login.html')


@login_required
def update_member_view(request, id):
    user = Users.objects.get(email=request.session['email'])
    member = get_object_or_404(Users, id=id)

    if request.method == "POST":
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        is_active = 'is_active' in request.POST

        if Users.objects.filter(email=email).exclude(id=member.id).exists():
            messages.warning(request, "This email is already used by another user.")
            return redirect('update_member_view', id=member.id)

        if Users.objects.filter(phone=phone).exclude(id=member.id).exists():
            messages.warning(request, "This phone number is already used by another user.")
            return redirect('update_member_view', id=member.id)

        member.first_name = first_name
        member.last_name = last_name
        member.email = email
        member.phone = phone
        member.is_active = is_active
        member.save()

        messages.success(request, "Member updated successfully!")
        return redirect('members_view')

    context = {'member': member, 'user': user}
    return render(request, 'update_member.html', context)


@role_required('superuser')
def delete_member_view(request, id):
    member = Users.objects.get(id=id)
    messages.success(request, f"{member.first_name} {member.last_name} Deleted Successfully")
    member.delete()
    return redirect("members_view")


@login_required
def income_view(request):
    user = Users.objects.get(email=request.session['email'])
    superuser = user if user.is_superuser else user.created_by
    if request.method == "POST":
        date_str = request.POST['date']
        amount = request.POST['income_amount']
        date = datetime.datetime.strptime(date_str, '%Y-%m-%d').date()

        if date > timezone.now().date():
            messages.warning(request, "Future dates are not allowed!")
            return redirect('income_view')
        IncomeModel.objects.create(
            user=Users.objects.get(id=user.id),
            date=date,
            amount=amount
        )
        return redirect('income_view')
    if user.is_superuser:
        members = list(Users.objects.filter(created_by=superuser))
        if superuser not in members:
            members.append(superuser)
    else:
        members = [user]
    get_income = IncomeModel.objects.filter(user__in=members).filter(
        date__range=[datetimeinfo.convert_date_format(start_date_of_month),
                     datetimeinfo.convert_date_format(current_date_of_month)]).order_by('-created_at')
    context = {
        'members': members,
        'get_income': get_income,
        'user': user,
        'start_date_of_month': datetimeinfo.convert_date_format(start_date_of_month),
        'current_date_of_month': datetimeinfo.convert_date_format(current_date_of_month)
    }
    return render(request, 'income.html', context)


@login_required
def income_date_filter(request):
    if request.method == "POST":
        user = Users.objects.get(email=request.session['email'])
        superuser = user if user.is_superuser else user.created_by
        if user.is_superuser:
            members = list(Users.objects.filter(created_by=superuser))
            if superuser not in members:
                members.append(superuser)
        else:
            members = [user]
        get_income = IncomeModel.objects.filter(user__in=members)
        context = {'user': user, 'members': members}
        if 'date_chk_box' in request.POST:
            try:
                startdate = request.POST['startdate']
                enddate = request.POST['enddate']
                get_income = get_income.filter(date__range=[startdate, enddate])
                context.update({
                    'start_date_of_month': startdate,
                    'current_date_of_month': enddate,
                    'get_income': get_income
                })
            except Exception:
                messages.warning(request, "Invalid or Empty Date!")
                return redirect('income_view')
        if 'member_chk_box' in request.POST and user.is_superuser:
            try:
                member = request.POST['member']
                get_income = get_income.filter(user_id=member)
                context['get_income'] = get_income
            except Exception:
                messages.warning(request, "Invalid or Empty Member!")
                return redirect('income_view')
        return render(request, 'income.html', context)
    return HttpResponseNotAllowed(['POST'])


@login_required
def expenses_view(request):
    user = Users.objects.get(email=request.session['email'])
    superuser = user if user.is_superuser else user.created_by
    categories = Category.objects.all()

    if request.method == 'POST':
        try:
            date_str = request.POST['date']
            amount = request.POST['income_amount']
            description = request.POST['description']
            category_id = request.POST['category']
            date = datetime.datetime.strptime(date_str, '%Y-%m-%d').date()

            if date > timezone.now().date():
                messages.warning(request, "Future dates are not allowed!")
                return redirect('expenses_view')

            Expenses.objects.create(
                user=Users.objects.get(id=user.id),
                category_id_id=category_id,
                date=date,
                amount=amount,
                description=description
            )
            return redirect('expenses_view')

        except Exception as e:
            messages.error(request, f"Error adding expense: {e}")
            return redirect('expenses_view')

    if user.is_superuser:
        members = list(Users.objects.filter(created_by=superuser))
        if superuser not in members:
            members.append(superuser)
    else:
        members = [user]

    get_expenses = Expenses.objects.filter(user__in=members).filter(
        date__range=[
            datetimeinfo.convert_date_format(start_date_of_month),
            datetimeinfo.convert_date_format(current_date_of_month)
        ]
    ).order_by('-date')

    context = {
        'user': user,
        'categories': categories,
        'get_expenses': get_expenses,
        'members': members,
        'start_date_of_month': datetimeinfo.convert_date_format(start_date_of_month),
        'current_date_of_month': datetimeinfo.convert_date_format(current_date_of_month)
    }

    return render(request, 'expense.html', context)


@login_required
def expense_date_filter(request):
    if request.method == "POST":
        user = Users.objects.get(email=request.session['email'])
        superuser = user if user.is_superuser else user.created_by
        if user.is_superuser:
            members = list(Users.objects.filter(created_by=superuser))
            if superuser not in members:
                members.append(superuser)
        else:
            members = [user]
        get_expenses = Expenses.objects.filter(user__in=members)
        categories = Category.objects.all()
        context = {'user': user, 'members': members, 'categories': categories}
        if 'date_chk_box' in request.POST:
            try:
                startdate = request.POST['startdate']
                enddate = request.POST['enddate']
                get_expenses = get_expenses.filter(date__range=[startdate, enddate])
                context.update({
                    'start_date_of_month': startdate,
                    'current_date_of_month': enddate,
                    'get_expenses': get_expenses
                })
            except Exception:
                messages.warning(request, "Invalid or Empty Date!")
                return redirect('expenses_view')
        if 'category_chk_box' in request.POST:
            try:
                category = request.POST['category']
                get_expenses = get_expenses.filter(category_id_id=category)
                context['get_expenses'] = get_expenses
            except:
                messages.warning(request, "Invalid or Empty Category!")
                return redirect('expenses_view')
        if 'member_chk_box' in request.POST and user.is_superuser:
            try:
                member = request.POST['member']
                get_expenses = get_expenses.filter(user_id=member)
                context['get_expenses'] = get_expenses
            except:
                messages.warning(request, "Invalid or Empty Member!")
                return redirect('expenses_view')
        return render(request, 'expense.html', context)
    return HttpResponseNotAllowed(['POST'])


@login_required
def update_income_view(request, id):
    user = Users.objects.get(email=request.session['email'])
    superuser = user if user.is_superuser else user.created_by

    try:
        get_income = IncomeModel.objects.get(id=id)
    except ObjectDoesNotExist:
        messages.warning(request, "Income record not found.")
        return redirect('income_view')
    if not (user.is_superuser or get_income.user == user or get_income.user.created_by == user):
        messages.warning(request, "You are not allowed to edit this record.")
        return redirect('income_view')

    if user.is_superuser:
        members = list(Users.objects.filter(created_by=superuser))
        if superuser not in members:
            members.append(superuser)
    else:
        members = [user]

    if request.method == "POST":
        get_income.date = request.POST['date']
        get_income.amount = request.POST['income_amount']

        date = datetime.datetime.strptime(request.POST['date'], '%Y-%m-%d').date()
        if date > timezone.now().date():
            messages.warning(request, "Future dates are not allowed!")
            return redirect('update_income_view', id=id)

        if user.is_superuser:
            get_income.user_id = request.POST['member']

        get_income.save()
        messages.success(request, "Income Updated Successfully!")
        return redirect('income_view')

    context = {'income': get_income, 'user': user, 'members': members}
    return render(request, 'update_income.html', context)


@login_required
def delete_income_view(request, id):
    get_income = IncomeModel.objects.get(id=id)
    get_income.delete()
    messages.success(request, "Income Deleted Successfully!")
    return redirect('income_view')


@login_required
def update_expense_view(request, id):
    user = Users.objects.get(email=request.session['email'])
    superuser = user if user.is_superuser else user.created_by

    try:
        get_expense = Expenses.objects.get(id=id)
    except Expenses.DoesNotExist:
        messages.warning(request, "Expense record not found.")
        return redirect('expenses_view')

    if not (user.is_superuser or get_expense.user == user or get_expense.user.created_by == user):
        messages.warning(request, "You are not allowed to edit this record.")
        return redirect('expenses_view')

    if user.is_superuser:
        members = list(Users.objects.filter(created_by=superuser))
        if superuser not in members:
            members.append(superuser)
    else:
        members = [user]
    categories = Category.objects.all()

    if request.method == "POST":
        try:
            date = datetime.datetime.strptime(request.POST['date'], '%Y-%m-%d').date()
            if date > timezone.now().date():
                messages.warning(request, "Future dates are not allowed!")
                return redirect('update_expense_view', id=id)
        except ValueError:
            messages.warning(request, "Invalid date format!")
            return redirect('update_expense_view', id=id)

        get_expense.date = request.POST['date']
        get_expense.amount = request.POST['expense_amount']
        get_expense.description = request.POST['description']
        get_expense.category_id_id = request.POST['category']

        if user.is_superuser:
            get_expense.user_id = request.POST['member']

        get_expense.save()
        messages.success(request, "Expense Updated Successfully!")
        return redirect('expenses_view')

    context = {
        'getexpense': get_expense,
        'user': user,
        'members': members,
        'categories': categories
    }
    return render(request, 'update_expense.html', context)


@login_required
def delete_expense_view(request, id):
    try:
        get_expense = Expenses.objects.get(id=id)
        get_expense.delete()
        messages.success(request, "Expense Deleted Successfully!")
    except Expenses.DoesNotExist:
        messages.error(request, "Expense does not exist!")
    return redirect('expenses_view')


@login_required
def download_income_report(request):
    user = Users.objects.get(email=request.session['email'])
    superuser = user if user.is_superuser else user.created_by
    members = Users.objects.filter(created_by=superuser) if user.is_superuser else [user]
    get_income = IncomeModel.objects.filter(user__in=members).filter(
        date__range=[datetimeinfo.convert_date_format(start_date_of_month),
                     datetimeinfo.convert_date_format(current_date_of_month)])
    total_income = get_income.aggregate(total_amount=Sum('amount'))['total_amount'] or 0

    workbook = openpyxl.Workbook()
    worksheet = workbook.active
    worksheet.title = 'Income Report'
    worksheet.append(['Member Name', 'Income Date', 'Total Income'])
    for income in get_income:
        worksheet.append([f"{income.user.first_name} {income.user.last_name}", income.date, income.amount])
    worksheet.append(['Total', '', total_income])

    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename=income_report.xlsx'
    workbook.save(response)
    return response


@login_required
def download_expense_report(request):
    user = Users.objects.get(email=request.session['email'])
    superuser = user if user.is_superuser else user.created_by
    members = Users.objects.filter(created_by=superuser) if user.is_superuser else [user]
    get_expenses = Expenses.objects.filter(user__in=members).filter(
        date__range=[datetimeinfo.convert_date_format(start_date_of_month),
                     datetimeinfo.convert_date_format(current_date_of_month)])
    total_expense = get_expenses.aggregate(total_amount=Sum('amount'))['total_amount'] or 0

    workbook = openpyxl.Workbook()
    worksheet = workbook.active
    worksheet.title = 'Expense Report'
    worksheet.append(['Member Name', 'Expense Date', 'Category', 'Expense'])
    for expense in get_expenses:
        worksheet.append([f"{expense.user.first_name} {expense.user.last_name}", expense.date, expense.category_id.name,
                          expense.amount])
    worksheet.append(['Total', '', '', total_expense])

    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename=expense_report.xlsx'
    workbook.save(response)
    return response
