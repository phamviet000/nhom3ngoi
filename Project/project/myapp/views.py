import threading

from django.contrib.auth.forms import AuthenticationForm
from django.shortcuts import render, redirect
from django.contrib import messages



def index(request):
    return render(request, 'myapp/home.html')

#tien test git hub....qeq
