from django.conf import settings
from datetime import datetime
import pytz

class CurrentDateTime():
    def __init__(self):
        self.timezone = settings.TIME_ZONE 
        self.format_of_datetime = '%d-%m-%Y %H:%M:%S'

    def get_current_datetime(self):
        """
        Returns the current date and time formatted as a string in the specified timezone.

        This function retrieves the current date and time in the timezone specified by
        the Django settings.TIME_ZONE variable. It formats the date and time as
        'dd-mm-yyyy HH:MM:SS' (24-hour format) and returns the formatted string.

        Returns:
            str: A string representing the current date and time in the format 'dd-mm-yyyy HH:MM:SS'.

        Raises:
            ValueError: If the timezone specified in settings.TIME_ZONE is invalid or not recognized.
        """
        formatted_datetime = datetime.now(pytz.timezone(self.timezone)).strftime(self.format_of_datetime)
        return formatted_datetime
    
    def get_current_date(self):
        """
        Returns the current date extracted from the current date and time string.

        This function extracts the date part from the current date and time string
        returned by the get_current_datetime() method.

        Returns:
            str: A string representing the current date in the format 'dd-mm-yyyy'.
        """
        formatted_date = self.get_current_datetime()
        return formatted_date.split(' ')[0]
    
    def get_current_time(self):
        """
        Returns the current time extracted from the current date and time string.

        This function extracts the time part from the current date and time string
        returned by the get_current_datetime() method.

        Returns:
            str: A string representing the current time in the format 'HH:MM:SS'.
        """
        formatted_time = self.get_current_datetime()
        return formatted_time.split(' ')[1]

class DateTimeInformation(CurrentDateTime):
    def get_startdate_of_month(self):
        """
        Returns the start date of the current month.

        This function calculates the start date of the current month
        and returns it in the format 'dd-mm-yyyy'.

        Returns:
            str: A string representing the start date of the current month in the format 'dd-mm-yyyy'.
        """
        start_date_of_month = datetime.now().replace(day=1).strftime('%d-%m-%Y')
        return start_date_of_month
    
    def convert_date_format(self,date_str):
        """
        Parse the date string and convert it to "YYYY-MM-DD" format

        """
        parsed_date = datetime.strptime(date_str, "%d-%m-%Y").date()
        converted_date_str = parsed_date.strftime("%Y-%m-%d")
        return converted_date_str
    
