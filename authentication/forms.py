from django import forms
from .models import Users

class MembersForm(forms.ModelForm):
    class Meta:
        model = Users
        fields = ['first_name','last_name','email','phone','is_active']
        widgets = {
            'first_name' : forms.TextInput(attrs={
                'id' : 'firstname',
                'placeholder' : 'Eric',
                'class' : "form-control border"
            }),
            'last_name' : forms.TextInput(attrs={
                'id' : 'lasttname',
                'placeholder' : 'Patel',
                'class' : "form-control border"
            }),
            'email' : forms.TextInput(attrs={
                'id' : 'email',
                'placeholder' : 'Example@gmail.com',
                'class' : "form-control border"
            }),
            'phone' : forms.TextInput(attrs={
                'id' : 'phone',
                'placeholder' : '(+91) XXX XXXX XXX',
                'class' : "form-control border"
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            self.fields['is_active'].initial = self.instance.is_active
