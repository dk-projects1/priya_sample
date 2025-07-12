from django.urls import path, register_converter, include
from . import views
from . converters import ObjectIdConverter

register_converter(ObjectIdConverter, 'ObjectId')


urlpatterns = [
    path('signup/', views.signup, name='signup'),\
    path('', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('home/', views.home, name='home'),
    path('admin/', views.admin, name='admin'),
    path('otp_verify/', views.otp_verify, name='otp_verify'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('forgot_otp_verify/', views.forgot_otp_verify, name='forgot_otp_verify'),    
    path('edit_post/<ObjectId:post_id>/', views.edit_post, name='edit_post'),
    path('delete_post/<ObjectId:post_id>/', views.delete_post, name='delete_post'),
    path('appoinment/', views.appoinments, name='appoinments'),
    path('<ObjectId:post_id>/', views.view_product, name='view_product'),
]