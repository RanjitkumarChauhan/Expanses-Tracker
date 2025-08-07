from account.models import Expenses, IncomeModel
from authentication.models import Users
from master.utils.ME_DATETIME.me_time import DateTimeInformation
from django.db.models import Sum


class IncomeExpense:
    def __init__(self, id):
        self.id = id
        self.datetimeinfo = DateTimeInformation()
        self.start_date_of_month = self.datetimeinfo.get_startdate_of_month()
        self.current_date_of_month = self.datetimeinfo.get_current_date()
        self.getmember = Users.objects.filter(user=id)

    def current_total_income(self):
        current_total_income = 0
        for member in self.getmember:
            getincome = IncomeModel.objects.filter(member_id_id=member.id).filter(
                date__range=[self.datetimeinfo.convert_date_format(self.start_date_of_month),
                             self.datetimeinfo.convert_date_format(self.current_date_of_month)])
            current_total_income += getincome.aggregate(total_amount=Sum('amount'))['total_amount'] or 0
        return current_total_income

    def current_total_expense(self):
        current_total_expense = 0
        for member in self.getmember:
            getexpense = Expenses.objects.filter(member_id_id=member.id).filter(
                date__range=[self.datetimeinfo.convert_date_format(self.start_date_of_month),
                             self.datetimeinfo.convert_date_format(self.current_date_of_month)])
            current_total_expense += getexpense.aggregate(total_amount=Sum('amount'))['total_amount'] or 0
        return current_total_expense
