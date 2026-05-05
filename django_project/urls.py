"""
URL configuration for django_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.db.models import Index
from django.contrib import admin
from django.urls import path, include
from tasks import views # Импорт представлений из приложения tasks.


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('accesssecurity.urls')),
    path("", views.index), # Добавление маршрута для корневого URL-адреса, который будет обрабатываться функцией index из представлений приложения tasks. (для работы необходимо создать функцию index в файле views.py)
]
