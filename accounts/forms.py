from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User

class SignupForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ("username", "email")

class LoginForm(AuthenticationForm):
    pass

class TOTPForm(forms.Form):
    token = forms.CharField(
        max_length=6,
        min_length=6,
        label="6-Digit Verification Code",
        widget=forms.TextInput(attrs={'placeholder': '123456', 'maxlength': '6'})
    )
