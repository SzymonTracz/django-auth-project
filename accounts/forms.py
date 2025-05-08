from django import forms
from .models import User

class UserRegistrationForm(forms.ModelForm):
    username = forms.CharField(
        label="Nazwa użytkownika",
        help_text=None 
    )
    email = forms.EmailField(label="Adres e-mail")
    password = forms.CharField(
        label="Hasło",
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'})
    )
    password_confirm = forms.CharField(
        label="Potwierdź hasło",
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'})
    )
    first_name = forms.CharField(label="Imię", max_length=150, required=False)
    last_name = forms.CharField(label="Nazwisko", max_length=150, required=False)
    terms_accepted = forms.BooleanField(
        label="Akceptuję Ogólne Warunki Świadczenia Usług",
        required=True
    )
    newsletter_consent = forms.BooleanField(
        label="Wyrażam zgodę na otrzymywanie e-maili",
        required=False
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'password', 'password_confirm', 'terms_accepted', 'newsletter_consent']
        
        help_texts = {
            'username': None, 
        }


    def clean_password_confirm(self):
        cd = self.cleaned_data
        if cd.get('password') and cd.get('password_confirm') and cd['password'] != cd['password_confirm']:
            raise forms.ValidationError("Hasła nie są identyczne.")
        return cd.get('password_confirm')

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("Ten adres email jest już używany.")
        return email
    
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("Ta nazwa użytkownika jest już zajęta.")
        return username

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])
        user.is_active = True
        if commit:
            user.save()
        return user

class CustomLoginForm(forms.Form):
    username = forms.CharField(label="Nazwa użytkownika lub adres e-mail")
    password = forms.CharField(widget=forms.PasswordInput(attrs={'autocomplete': 'current-password'}), label="Hasło")

class EmailVerificationForm(forms.Form):
    code = forms.CharField(
        label="Kod weryfikacyjny", 
        max_length=6,
        widget=forms.TextInput(attrs={'placeholder': 'XXXXXX', 'autocomplete': 'one-time-code'})
    )

class TOTPVerificationForm(forms.Form):
    code = forms.CharField(
        label="Kod z aplikacji uwierzytelniającej (6 cyfr)", 
        max_length=6,
        widget=forms.TextInput(attrs={'placeholder': '123456', 'autocomplete': 'one-time-code', 'inputmode': 'numeric'})
    )