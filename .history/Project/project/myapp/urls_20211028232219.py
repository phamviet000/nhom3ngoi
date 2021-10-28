from django.urls import path
from . import views

app_name = 'myapp'
urlpatterns = [
    path('', views.index),
    path('login/', LoginClass.as_view(), name='login'),
]
