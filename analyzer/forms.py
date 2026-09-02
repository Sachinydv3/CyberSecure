from django import forms


class PasswordForm(forms.Form):
    """Form used by the server-side (no-JS) analyzer fallback."""

    password = forms.CharField(
        min_length=1,
        max_length=256,
        widget=forms.PasswordInput(
            attrs={
                "id": "password-input",
                "autocomplete": "new-password",
                "class": "form-control",
                "placeholder": "Enter a password to analyze",
                "spellcheck": "false",
                "autocapitalize": "off",
            }
        ),
    )
    consent = forms.BooleanField(
        required=True,
        label=(
            "I understand my password will be hashed (SHA-256) "
            "and stored for reuse detection."
        ),
    )
