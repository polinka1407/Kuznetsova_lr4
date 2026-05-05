from django.shortcuts import render

# Create your views here.

def index(request):
  return render(request, "index.html") # Создание функции index, которая принимает объект запроса request и возвращает результат вызова функции render, которая рендерит шаблон index.html.