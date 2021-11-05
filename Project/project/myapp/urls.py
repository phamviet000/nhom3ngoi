from django.urls import path
from . import views
from .views import LoginClass,RegistrationView,ActivateAccountView,ViewUser,edit_profile
app_name = 'myapp'
urlpatterns = [
    path('', views.index, name='home'),
    path('login/', LoginClass.as_view(), name='login'),
    path('change/',views.change,name='change'),
    path('logout/', views.logoutuser, name='logout'),
    path('signup/',RegistrationView.as_view(),name='signup'),
    path('activate/<uidb64>/<token>/', ActivateAccountView.as_view(), name='activate'),
    path('account/', ViewUser.as_view(), name='account'),
    path('profile-form', edit_profile.as_view(), name='profile-form'),

]
