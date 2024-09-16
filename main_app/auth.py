from supabase import create_client
from django.conf import settings

supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

def signup_user(email, password):
    return supabase.auth.sign_up({'email': email, 'password': password})

def login_user(email, password):
    return supabase.auth.sign_in(email=email, password=password)

def reset_password(email):
    return supabase.auth.api.reset_password_for_email(email)
