
from django.urls import path
from . import views

urlpatterns = [
   
    path('forms/', views.login_register_combined_view, name='login_register_forms_page'),

    # Akcja dla formularza rejestracji
    path('register/', views.register_view, name='register'), 

    # Akcja dla pierwszego etapu logowania
    path('login/', views.login_step1_credentials_view, name='login_step1_credentials'), 

    # Kroki logowania MFA
    path('login/verify-email/', views.login_step2_email_code_view, name='login_step2_email_code'),
    path('login/verify-totp/', views.login_step3_totp_code_view, name='login_step3_totp_code'),

    path('logout/', views.logout_view, name='logout'),

    path('profile/totp/setup/', views.setup_totp_view, name='setup_totp'),
    path('profile/totp/disable/', views.disable_totp_view, name='disable_totp'),
    path('profile/', views.profile_view, name='profile'),
]