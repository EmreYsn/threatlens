from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class RegisterForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'placeholder': 'email@example.com',
        })
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({'placeholder': 'kullaniciadi'})
        self.fields['password1'].widget.attrs.update({'placeholder': '••••••••'})
        self.fields['password2'].widget.attrs.update({'placeholder': '••••••••'})


class IOCSearchForm(forms.Form):
    """Ana arama formu"""
    query = forms.CharField(
        max_length=2048,
        widget=forms.TextInput(attrs={
            'placeholder': 'IP, domain, URL, hash veya email girin...',
            'autocomplete': 'off',
            'autofocus': True,
            'id': 'ioc-input',
        }),
        label='',
    )


class NoteForm(forms.Form):
    """IOC not ekleme formu"""
    content = forms.CharField(
        widget=forms.Textarea(attrs={
            'placeholder': 'Bu IOC hakkında not ekleyin...',
            'rows': 3,
        }),
        label='',
    )

class CSVUploadForm(forms.Form):
    csv_file = forms.FileField(
        label='CSV Dosyası',
        help_text='Her satırda bir IOC olmalı. Maksimum 50 IOC.',
        widget=forms.FileInput(attrs={
            'accept': '.csv,.txt',
        })
    )

class RegisterForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'placeholder': 'email@example.com',
        })
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({'placeholder': 'kullaniciadi'})
        self.fields['password1'].widget.attrs.update({'placeholder': '••••••••'})
        self.fields['password2'].widget.attrs.update({'placeholder': '••••••••'})