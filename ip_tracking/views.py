from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited


@ratelimit(key='ip', rate='5/m', method=['GET', 'POST'], block=True)
def login_view(request):
    """
    Login view with rate limiting:
    - 5 requests per minute for anonymous users
    - Will be overridden to 10/m for authenticated users in other views
    """
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome back, {username}!')
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = AuthenticationForm()
    
    return render(request, 'ip_tracking/login.html', {'form': form})


@ratelimit(key='ip', rate='10/m', method=['GET', 'POST'], block=True)
def dashboard_view(request):
    """
    Dashboard view with rate limiting:
    - 10 requests per minute for authenticated users
    """
    if not request.user.is_authenticated:
        return redirect('login')
    
    return render(request, 'ip_tracking/dashboard.html', {
        'user': request.user,
        'title': 'Dashboard'
    })


@ratelimit(key='ip', rate='5/m', method=['GET'], block=True)
def api_status(request):
    """
    API status endpoint with rate limiting for anonymous users.
    """
    return JsonResponse({
        'status': 'ok',
        'authenticated': request.user.is_authenticated,
        'user': request.user.username if request.user.is_authenticated else None
    })


def ratelimited_error(request, exception):
    """
    Custom handler for rate limited requests.
    """
    return JsonResponse({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.',
        'status': 429
    }, status=429)
