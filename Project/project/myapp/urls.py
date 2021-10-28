from django.urls import path
from . import views
from .views import LoginClass
app_name = 'myapp'
urlpatterns = [
    path('', views.index, name='home'),
    path('login/', LoginClass.as_view(), name='login'),
    path('logout/', views.logoutuser, name='logout'),
]
