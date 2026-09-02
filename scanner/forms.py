from django import forms


SCAN_TYPE_CHOICES = [
    ("full", "Full scan (HTTP + ports)"),
    ("http", "HTTP checks only"),
    ("ports", "Port scan only"),
]


class ScanForm(forms.Form):
    """Form for the Vulnerability Scanner.

    Mirrors :class:`analyzer.forms.PasswordForm` in shape — single Form
    (not ModelForm), widget attrs baked in, an explicit consent checkbox
    gating the submit button.
    """

    target = forms.URLField(
        min_length=1,
        max_length=2048,
        widget=forms.URLInput(
            attrs={
                "id": "target-input",
                "class": "form-control",
                "placeholder": "https://example.com or http://127.0.0.1:8000",
                "autocomplete": "off",
                "spellcheck": "false",
                "autocapitalize": "off",
                "inputmode": "url",
            }
        ),
        help_text="A full URL — scheme + host (+ optional port/path).",
    )

    scan_type = forms.ChoiceField(
        choices=SCAN_TYPE_CHOICES,
        initial="full",
        widget=forms.Select(attrs={"id": "scan-type", "class": "form-control"}),
    )

    localhost_only = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={"id": "localhost-only"}),
        label="Restrict port scan to loopback / private IPs",
        help_text=(
            "Recommended when scanning a local development server. Disable "
            "only if you are explicitly authorised to scan the target."
        ),
    )

    consent = forms.BooleanField(
        required=True,
        widget=forms.CheckboxInput(attrs={"id": "consent"}),
        label=(
            "I confirm I own or am authorised to test this target. "
            "Unauthorised scanning may be illegal."
        ),
    )

    def clean_target(self):
        url = self.cleaned_data["target"]
        # URLField already parses, but apply our own length + scheme check
        # so we have a single source of truth.
        from .http_checks import is_safe_url
        if not is_safe_url(url):
            raise forms.ValidationError(
                "Enter a full URL beginning with http:// or https://."
            )
        return url
