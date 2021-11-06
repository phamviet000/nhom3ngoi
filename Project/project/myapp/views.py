import threading
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib import messages
from validate_email import validate_email
from .models import MyUser
from django.contrib.auth.forms import AuthenticationForm
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from .models import MyUser
from .utils import generate_token
from django.core.mail import EmailMessage
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from datetime import date
import datetime


def index(request):
    return render(request, 'myapp/home.html')

class EmailThread(threading.Thread):

    def __init__(self, email_message):
        self.email_message = email_message
        threading.Thread.__init__(self)

    def run(self):
        self.email_message.send()

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
            messages.add_message(request, messages.ERROR,
                                  'Username is required')
            messages.warning(request, 'Username is required')
            context['has_error'] = True
        if password == '':
            messages.add_message(request, messages.ERROR,
                                 'Password is required')
            messages.warning(request, 'Password is required')
            context['has_error'] = True
        user = authenticate(request, username=username, password=password)
        if not user and not context['has_error']:
            messages.add_message(request, messages.ERROR, 'Invalid login')
            #messages.warning(request, 'Invalid login')
            context['has_error'] = True
        if context['has_error']:
            return render(request, 'myapp/login.html', status=401, context=context)
        login(request, user)
        # return redirect('myapp:account')
        return redirect('myapp:home')

class RegistrationView(View):
    def get(self,request):
        return  render(request,'myapp/signup.html')

    def post(self,request):
        context = {'data':request.POST,'has_error':False}
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        if password != password2:
            messages.add_message(request, messages.ERROR,'Password are not the same')
            context['has_error'] = True

        # if not validate_email(email):
        #     messages.add_message(request,messages.ERROR,'Please privide a vlid email')
        #     context['has_error'] = True
        try:
            if MyUser.objects.filter(email=email):
                messages.add_message(request, messages.ERROR, 'Email is taken')
                context['has_error'] = True
        except Exception as identifier:
            pass
        try:
            if MyUser.objects.filter(username=username):
                messages.add_message(request,messages.ERROR,'User is taken')
                context['has_error'] = True
        except Exception as identifier:
            pass

        if context['has_error']:
            return render(request, 'myapp/signup.html', context,status=400)

        user = MyUser.objects.create_user(username=username,email=email)
        user.set_password(password)
        user.is_active= False

        user.save()

        current_site = get_current_site(request)
        email_subject = 'Active your Account'
        message = render_to_string('myapp/activate.html',
                                   {
                                       'user': user,
                                       'domain': current_site.domain,
                                       'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                                       'token': generate_token.make_token(user)
                                   }
                                   )

        email_message = EmailMessage(
            email_subject,
            message,
            settings.EMAIL_HOST_USER,
            [email]
        )


        EmailThread(email_message).start()
        messages.add_message(request, messages.SUCCESS,
                             'Account creating sucessfully')

        return redirect('myapp:login')

class RequestResetEmailView(View):
    def get(self, request):
        return render(request, 'myapp/find-account.html')

    def post(self, request):
        email = request.POST['email']

        if not validate_email(email):
            messages.error(request, 'Please enter a valid email')
            return render(request, 'mmyapp/find-account.html')

        user = MyUser.objects.filter(email=email)

        if user.exists():
            current_site = get_current_site(request)
            email_subject = '[Reset your Password]'
            message = render_to_string('myapp/reset-user-password.html',
                                       {
                                           'domain': current_site.domain,
                                           'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                                           'token': PasswordResetTokenGenerator().make_token(user[0])
                                       }
                                       )

            email_message = EmailMessage(
                email_subject,
                message,
                settings.EMAIL_HOST_USER,
                [email]
            )

            EmailThread(email_message).start()

        messages.success(
            request, 'We have sent you an email with instructions on how to reset your password')
        return render(request, 'myapp/find-account.html')

#Kích hoạt tài khoảng
class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = MyUser.objects.get(pk=uid)
        except Exception as identifier:
            user = None
        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.add_message(request, messages.SUCCESS,
                                 'Account activated successfully')
            return redirect('myapp:login')
        return render(request, 'myapp/activate_failed.html', status=401)

class RequestResetEmailView(View):
    def get(self, request):
        return render(request, 'myapp/find-account.html')

    def post(self, request):
        email = request.POST['email']

        if not validate_email(email):
            messages.error(request, 'Please enter a valid email')
            return render(request, 'myapp/find-account.html')

        user = MyUser.objects.filter(email=email)

        if user.exists():
            current_site = get_current_site(request)
            email_subject = '[Reset your Password]'
            message = render_to_string('myapp/reset-user-password.html',
                                       {
                                           'domain': current_site.domain,
                                           'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                                           'token': PasswordResetTokenGenerator().make_token(user[0])
                                       }
                                       )

            email_message = EmailMessage(
                email_subject,
                message,
                settings.EMAIL_HOST_USER,
                [email]
            )

            EmailThread(email_message).start()

        messages.success(
            request, 'We have sent you an email with instructions on how to reset your password')
        return render(request, 'myapp/find-account.html')
class SetNewPasswordView(View):
    def get(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }

        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))

            user = MyUser.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.info(
                    request, 'Password reset link, is invalid, please request a new one')
                return render(request, 'myapp/request-reset-email.html')

        except DjangoUnicodeDecodeError as identifier:
            messages.success(
                request, 'Invalid link')
            return render(request, 'myapp/request-reset-email.html')

        return render(request, 'myapp/set-new-password.html', context)

    def post(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token,
            'has_error': False
        }

        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        if len(password) < 6:
            messages.add_message(request, messages.ERROR,
                                 'passwords should be at least 6 characters long')
            context['has_error'] = True
        if password != password2:
            messages.add_message(request, messages.ERROR,
                                 'passwords don`t match')
            context['has_error'] = True

        if context['has_error'] == True:
            return render(request, 'myapp/set-new-password.html', context)

        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))

            user = MyUser.objects.get(pk=user_id)
            user.set_password(password)
            user.save()

            messages.success(
                request, 'Password reset success, you can login with new password')

            return redirect('myapp:login')

        except DjangoUnicodeDecodeError as identifier:
            messages.error(request, 'Something went wrong')
            return render(request, 'myapp/set-new-password.html', context)

        return render(request, 'myapp/set-new-password.html', context)

class ViewUser(View):
    def get(self,request):
        if not request.user.is_authenticated:
            return redirect('myapp:login')
        else:
            return render(request, 'myapp/Profile.html')
def logoutuser(request):
    logout(request)
    return redirect('myapp:home')
class edit_profile(View):
    def get(self,request):
        return render(request, 'myapp/profile-form.html')
    def post(self,request):
        data = MyUser.objects.get(id=request.user.id)
        if request.method == "POST":
            first_name = request.POST.get('first_name')
            last_name = request.POST.get('last_name')
            phone_number = request.POST.get('phone_number')
            birdth_day = request.POST.get('birdth_day')
            sex = request.POST.get('sex')

            data.first_name = first_name
            data.last_name = last_name
            data.phone_number = phone_number
            data.sex = sex
            today = datetime.datetime.now()
            date_format = "%Y-%m-%d"
            try:
                dt = datetime.datetime.strptime(birdth_day, date_format)
                data.birdth_day = birdth_day
                if (dt < today):
                    day = date.today()
                    age = int(day.year - dt.year - ((day.month, day.day) < (dt.month, dt.day)))
                    if(age >= 18):
                        data.save()
                        messages.success(request,'Profile has been updated')
                        return redirect('myapp:profile-form')
                    else:
                        messages.warning(request, 'You not 18')
                        return redirect('myapp:profile-form')
                else:
                    messages.warning(request, 'Error Time')
                    return redirect('myapp:profile-form')
            except ValueError:
                data.save()
                messages.success(request, 'Profile has been updated')
                return redirect('myapp:profile-form')

        return redirect('myapp:profile-form')

