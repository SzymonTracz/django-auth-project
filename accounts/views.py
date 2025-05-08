from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout as auth_logout
from django.contrib import messages
from django.urls import reverse_lazy, reverse
from django.conf import settings
from django.contrib.auth.decorators import login_required
from .forms import UserRegistrationForm, CustomLoginForm, EmailVerificationForm, TOTPVerificationForm
from .models import User 

from django.contrib.auth.decorators import login_required
from django.conf import settings 
from django.core.mail import send_mail
import qrcode
import io
import base64
import pyotp 

# Funkcje pomocnicze 
def send_login_verification_email_django(user_email, code):
    subject = "Kod Weryfikacyjny Logowania - SystemApp"
    message = f"Twój jednorazowy kod logowania to: {code}"
    email_from = settings.DEFAULT_FROM_EMAIL
    recipient_list = [user_email]
    try:
        send_mail(subject, message, email_from, recipient_list)
        print(f"DEBUG: Email logowania wysłany do {user_email} z kodem {code}")
        return True
    except Exception as e:
        print(f"Błąd podczas wysyłania emaila logowania przez Django: {e}")
        return False

def login_register_combined_view(request):
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL) 
        
    login_form = CustomLoginForm()
    register_form = UserRegistrationForm()
    return render(request, 'accounts/login_register.html', {
        'login_form': login_form,
        'register_form': register_form
    })

def register_view(request):
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)

    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            messages.success(request, "Rejestracja zakończona pomyślnie. Zostałeś zalogowany.")
            
            request.session['just_registered_setup_totp'] = True 
            messages.info(request, "Proszę skonfigurować uwierzytelnianie dwuskładnikowe (TOTP) dla zwiększenia bezpieczeństwa.")
            return redirect('setup_totp')
        else:
            
            login_form = CustomLoginForm() 
            return render(request, 'accounts/login_register.html', {
                'login_form': login_form,
                'register_form': form 
            })
    else:
        return redirect('login_register_page')


# Widoki Logowania Wieloskładnikowego 
def login_step1_credentials_view(request):
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL) 

    if request.method == 'POST':
        form = CustomLoginForm(request.POST)
        if form.is_valid():
            username_or_email = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            
            user = authenticate(request, username=username_or_email, password=password) 
            
            if user is not None:
                if not user.is_active:
                    messages.error(request, "Twoje konto nie jest aktywne.")
                    current_login_form = CustomLoginForm(initial=request.POST) 
                    register_form = UserRegistrationForm()
                    return render(request, 'accounts/login_register.html', {
                        'login_form': current_login_form, 
                        'register_form': register_form
                    })

                request.session['mfa_user_id'] = user.id
                request.session['mfa_login_stage'] = 'email_code'

                verification_code = user.generate_email_verification_code()
               
                if send_login_verification_email_django(user.email, verification_code): 
                    messages.info(request, "Kod weryfikacyjny został wysłany na Twój adres email.")
                    return redirect('login_step2_email_code')
                else:
                    messages.error(request, "Nie udało się wysłać kodu weryfikacyjnego. Spróbuj ponownie później.")
                    current_login_form = CustomLoginForm(initial=request.POST)
                    register_form = UserRegistrationForm()
                    return render(request, 'accounts/login_register.html', {
                        'login_form': current_login_form, 
                        'register_form': register_form
                    })
            else: 
                messages.error(request, "Nieprawidłowa nazwa użytkownika lub hasło.")
                current_login_form = CustomLoginForm(initial=request.POST) 
                register_form = UserRegistrationForm()
                return render(request, 'accounts/login_register.html', {
                    'login_form': current_login_form, 
                    'register_form': register_form
                })
        else: 
            register_form = UserRegistrationForm() 
            return render(request, 'accounts/login_register.html', {
                'login_form': form, 
                'register_form': register_form
            })
    else: 
       
        return redirect('login_register_forms_page') 


def login_step2_email_code_view(request):
    if 'mfa_user_id' not in request.session or request.session.get('mfa_login_stage') != 'email_code':
        messages.error(request, "Sesja logowania wygasła lub jest nieprawidłowa. Zacznij od początku.")
        return redirect('login_register_page') 

    user_id = request.session['mfa_user_id']
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        messages.error(request, "Nie znaleziono użytkownika. Sesja nieprawidłowa.")
        request.session.flush()
        return redirect('login_register_page')

    if request.method == 'POST':
        form = EmailVerificationForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data.get('code')
            if user.verify_email_code(code):
                messages.success(request, "Kod email zweryfikowany.")
                if user.is_totp_enabled:
                    request.session['mfa_login_stage'] = 'totp_code'
                    return redirect('login_step3_totp_code')
                else:
                    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                    request.session.pop('mfa_user_id', None)
                    request.session.pop('mfa_login_stage', None)
                    messages.success(request, f"Witaj {user.get_username()}! Zostałeś pomyślnie zalogowany.")
                    return redirect(settings.LOGIN_REDIRECT_URL)
            else:
                messages.error(request, "Nieprawidłowy lub wygasły kod weryfikacyjny.")
    else:
        form = EmailVerificationForm()
    return render(request, 'accounts/login_step2_email_code.html', {'form': form})


def login_step3_totp_code_view(request):
    if 'mfa_user_id' not in request.session or request.session.get('mfa_login_stage') != 'totp_code':
        messages.error(request, "Sesja logowania wygasła lub jest nieprawidłowa. Zacznij od początku.")
        return redirect('login_register_page')

    user_id = request.session['mfa_user_id']
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        messages.error(request, "Nie znaleziono użytkownika. Sesja nieprawidłowa.")
        request.session.flush()
        return redirect('login_register_page')

    if not user.is_totp_enabled:
        messages.warning(request, "TOTP nie jest skonfigurowane dla tego konta. Logowanie zakończone.")
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        request.session.pop('mfa_user_id', None)
        request.session.pop('mfa_login_stage', None)
        return redirect(settings.LOGIN_REDIRECT_URL)

    if request.method == 'POST':
        form = TOTPVerificationForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data.get('code')
            if user.verify_totp_code(code): 
                messages.success(request, "Kod TOTP zweryfikowany.")
                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                request.session.pop('mfa_user_id', None)
                request.session.pop('mfa_login_stage', None)
                messages.success(request, f"Witaj {user.get_username()}! Zostałeś pomyślnie zalogowany.")
                return redirect(settings.LOGIN_REDIRECT_URL)
            else:
                messages.error(request, "Nieprawidłowy lub wygasły kod TOTP.")
    else:
        form = TOTPVerificationForm()
    return render(request, 'accounts/login_step3_totp_code.html', {'form': form})


def logout_view(request):
      auth_logout(request)
      messages.info(request, "Zostałeś pomyślnie wylogowany.")
      return redirect(settings.LOGOUT_REDIRECT_URL)


@login_required
def setup_totp_view(request):
    user = request.user
    is_first_setup = request.session.pop('just_registered_setup_totp', False)

    if request.method == 'POST':
        form = TOTPVerificationForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data.get('code')
            if user.totp_secret:
                totp = pyotp.TOTP(user.totp_secret)
                if totp.verify(code, valid_window=1):
                    user.is_totp_enabled = True
                    user.save(update_fields=['is_totp_enabled'])
                    messages.success(request, "Uwierzytelnianie dwuskładnikowe (TOTP) zostało włączone.")
                    if is_first_setup:
                        return redirect(settings.LOGIN_REDIRECT_URL) 
                    else:
                        return redirect('profile') 
                else:
                    messages.error(request, "Nieprawidłowy kod TOTP. Spróbuj ponownie.")
            else:
                messages.error(request, "Błąd: Sekret TOTP nie został wygenerowany.")
    else:
        form = TOTPVerificationForm()

    user.generate_totp_secret_if_none()
    provisioning_uri = user.get_totp_provisioning_uri()

    img = qrcode.make(provisioning_uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    context = {
        'form': form,
        'totp_secret': user.totp_secret,
        'qr_code_base64': qr_code_base64,
        'is_totp_enabled': user.is_totp_enabled,
        'is_first_setup': is_first_setup,
    }
    return render(request, 'accounts/setup_totp.html', context)

@login_required
def disable_totp_view(request):
    user = request.user
    if request.method == 'POST':
        user.is_totp_enabled = False
        user.totp_secret = None 
        user.save(update_fields=['is_totp_enabled', 'totp_secret'])
        messages.success(request, "Uwierzytelnianie dwuskładnikowe (TOTP) zostało wyłączone.")
        return redirect('profile')
    return render(request, 'accounts/disable_totp_confirm.html')

@login_required
def profile_view(request): 
    return render(request, 'accounts/profile.html')

@login_required 
def home_view(request):
    context = {
        'username': request.user.get_username(),
    }
    return render(request, 'accounts/home.html', context)