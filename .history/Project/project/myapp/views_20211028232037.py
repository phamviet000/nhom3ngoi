import threading
from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib import messages
from validate_email import validate_email
#from .models import MyUser
from django.contrib.auth.forms import AuthenticationForm
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from .utils import generate_token
from django.core.mail import EmailMessage
from django.conf import settings
from django.contrib.auth import authenticate, login, logout


def index(request):
    return render(request, 'myapp/home.html')


class LoginClass(View):
    def get(self, request):
        if request.user.is_authenticated:
            return render(request, 'myapp/home.html')
        else:
            return render(request, 'myapp/login.html')

    def post(self, request):
        context = {
            'data': request.POST,
            'has_error': False
        }
        username = request.POST.get('tendangnhap')
        password = request.POST.get('password')
        if username == '':
            # messages.add_message(request, messages.ERROR,
            #                      'Username is required')
            messages.warning(request, 'Username is required')
            context['has_error'] = True
        if password == '':
            # messages.add_message(request, messages.ERROR,
            #                      'Password is required')
            messages.warning(request, 'Password is required')
            context['has_error'] = True
        user = authenticate(request, username=username, password=password)
        if not user and not context['has_error']:
            #messages.add_message(request, messages.ERROR, 'Invalid login')
            messages.warning(request, 'Invalid login')
            context['has_error'] = True
        if context['has_error']:
            return render(request, 'myapp/login.html', status=401, context=context)
        login(request, user)
        return redirect('myapp:account')

# tien test git hub....qeq
# ewqeqw
