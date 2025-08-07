from django.db import models
from .utils.ME_DATETIME.me_time import CurrentDateTime

class BaseClass(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        time_instance = CurrentDateTime()
        if not self.id:
            self.created_at = self.updated_at = time_instance.get_current_datetime()
        else:
            self.updated_at = time_instance.get_current_datetime()
        super().save(*args,**kwargs)