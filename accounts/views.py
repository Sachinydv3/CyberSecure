import pyotp
import qrcode
import io
import base64
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from .forms import SignupForm, LoginForm, TOTPForm
from .models import UserProfile

def signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, "Account created successfully! Please log in.")
            return redirect('accounts:login')
        else:
            messages.error(request, "Please correct the errors in the form.")
    else:
        form = SignupForm()
    return render(request, 'accounts/signup.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()

            # Check if 2FA is enabled
            if hasattr(user, 'profile') and user.profile.is_2fa_enabled:
                # Store user ID in session temporarily and redirect to 2FA verification
                request.session['pre_2fa_user_id'] = user.id
                return redirect('accounts:verify_2fa')
            else:
                # Regular login
                login(request, user)
                messages.success(request, f"Welcome back, {user.username}!")
                return redirect('dashboard:home')
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = LoginForm()
    return render(request, 'accounts/login.html', {'form': form})

def verify_2fa(request):
    user_id = request.session.get('pre_2fa_user_id')
    if not user_id:
        return redirect('accounts:login')

    from django.contrib.auth.models import User
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return redirect('accounts:login')

    if request.method == 'POST':
        form = TOTPForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data['token']
            totp = pyotp.TOTP(user.profile.totp_secret)
            if totp.verify(token):
                # 2FA Success: Complete login
                login(request, user)
                # Clear temporary session
                del request.session['pre_2fa_user_id']
                messages.success(request, "2FA verification successful!")
                return redirect('dashboard:home')
            else:
                messages.error(request, "Invalid verification code. Please try again.")
    else:
        form = TOTPForm()

    return render(request, 'accounts/verify_2fa.html', {'form': form})

@login_required
def profile(request):
    user = request.user
    profile = user.profile

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'enable_2fa':
            # Generate new secret if none exists
            if not profile.totp_secret:
                profile.totp_secret = pyotp.random_base32()

            profile.is_2fa_enabled = True
            profile.save()
            messages.success(request, "2FA has been enabled.")
        elif action == 'disable_2fa':
            profile.is_2fa_enabled = False
            profile.save()
            messages.success(request, "2FA has been disabled.")

        return redirect('accounts:profile')

    # Generate QR Code for 2FA setup
    qr_image_base64 = None
    if profile.totp_secret:
        totp = pyotp.TOTP(profile.totp_secret)
        provisioning_url = totp.provisioning_uri(name=user.email, issuer_name="SecureCyber")

        # Generate QR code image
        img = qrcode.make(provisioning_url)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_image_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render(request, 'accounts/profile.html', {
        'user': user,
        'profile': profile,
        'qr_image_base64': qr_image_base64,
    })

def logout_view(request):
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect('dashboard:home')
