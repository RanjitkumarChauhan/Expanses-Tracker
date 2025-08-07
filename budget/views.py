from datetime import datetime

from django.contrib import messages
from django.shortcuts import redirect, render

from account.models import Expenses, IncomeModel
from authentication.models import Users
from budget.models import Budget


def budget_view(request):
    try:
        user = Users.objects.get(email=request.session['email'])
    except Users.DoesNotExist:
        messages.warning(request, "User does not exist.")
        return redirect('dashboard_view')

    if not user.is_superuser:
        messages.warning(request, "You do not have permission to view this page.")
        return redirect('dashboard_view')

    if request.method == "POST" and 'budget_amount' in request.POST:
        budget_amount = request.POST.get('budget_amount')
        if budget_amount:
            Budget.objects.update_or_create(
                user=user,
                defaults={'amount': budget_amount}
            )
            return redirect('budget-page')
        else:
            messages.error(request, "Budget amount cannot be empty.")

    budget = Budget.objects.filter(user=user).first()
    budget_amount = budget.amount if budget else None

    today = datetime.today()
    start_date_of_month = today.replace(day=1)
    current_date_of_month = today

    startdate = request.POST.get('startdate', start_date_of_month.strftime('%Y-%m-%d'))
    enddate = request.POST.get('enddate', current_date_of_month.strftime('%Y-%m-%d'))
    member_id = request.POST.get('member')

    try:
        startdate = datetime.strptime(startdate, '%Y-%m-%d')
        enddate = datetime.strptime(enddate, '%Y-%m-%d')
    except ValueError:
        messages.error(request, "Invalid date format. Using current month instead.")
        startdate = start_date_of_month
        enddate = current_date_of_month

    member_ids = list(Users.objects.filter(created_by=user).values_list('id', flat=True))
    member_ids.append(user.id)
    member_ids = list(set(member_ids))

    incomes = IncomeModel.objects.filter(user_id__in=member_ids, date__range=[startdate, enddate])
    expenses = Expenses.objects.filter(user_id__in=member_ids, date__range=[startdate, enddate])

    if member_id:
        try:
            member_id = int(member_id)
            if member_id not in member_ids:
                raise ValueError
            incomes = incomes.filter(user_id=member_id)
            expenses = expenses.filter(user_id=member_id)
        except (ValueError, TypeError):
            messages.error(request, "Invalid member selection.")
            member_id = None

    total_income = sum(income.amount for income in incomes) if incomes.exists() else 0
    total_expenses = sum(expense.amount for expense in expenses) if expenses.exists() else 0

    context = {
        'user': user,
        'budget_amount': budget_amount,
        'start_date_of_month': start_date_of_month.strftime('%Y-%m-%d'),
        'current_date_of_month': current_date_of_month.strftime('%Y-%m-%d'),
        'total_income': total_income,
        'total_expenses': total_expenses,
        'members': Users.objects.filter(created_by=user) | Users.objects.filter(id=user.id),
        'selected_startdate': startdate.strftime('%Y-%m-%d'),
        'selected_enddate': enddate.strftime('%Y-%m-%d'),
        'selected_member': member_id,
    }
    return render(request, 'budget.html', context)
