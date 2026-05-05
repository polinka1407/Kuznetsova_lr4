

from django.shortcuts import render
import random
import pandas as pd
import matplotlib.pyplot as plt
import io
import base64
import os
from datetime import datetime

# Настройка matplotlib для работы без GUI
import matplotlib
matplotlib.use('Agg')

def index(request):
    """Главная страница - форма авторизации"""

    SECRET_LOGIN = os.environ.get('SECRET_LOGIN', 'admin')
    SECRET_PASSWORD = os.environ.get('SECRET_PASSWORD', 'admin123')

    error_message = None

    if request.method == 'POST':
        user_login = request.POST.get('login')
        user_password = request.POST.get('password')

        if user_login == SECRET_LOGIN and user_password == SECRET_PASSWORD:
            return security_check(request)
        else:
            error_message = "❌ Доступ запрещён! Неверный логин или пароль."

    return render(request, 'accesssecurity/index.html', {'error': error_message})

def generate_chart_base64():
    """Вспомогательная функция для создания графиков в base64"""
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', bbox_inches='tight', dpi=100)
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.getvalue()).decode()
    plt.close()
    return image_base64

def security_check(request):
    """Контейнер расчёта - результаты анализа безопасности с графиками"""

    # Список сторонних сервисов 
    external_services = [
        "Google OAuth",
        "Facebook Login",
        "Payment Gateway",
        "Cloud Storage API",
        "CRM System",
        "Telegram Bot API",
        "Apple ID",
        "GitHub OAuth"
    ]

    n = len(external_services)

    # Генерация исходных данных
    requests_count = []
    token_valid = []
    suspicious_ip = []
    oauth_anomaly = []
    rate_exceeded = []
    token_reuse = []

    for _ in range(n):
        requests_count.append(random.randint(1, 200))
        token_valid.append(random.choice([0, 1]))
        suspicious_ip.append(random.choice([0, 1]))
        oauth_anomaly.append(random.choice([0, 1]))
        rate_exceeded.append(random.choice([0, 1]))
        token_reuse.append(random.choice([0, 1]))

    # Расчёт уровня риска НСД
    risk_level = []
    decision = []

    for i in range(n):
        risk = 0
        if requests_count[i] > 100:
            risk += 1
        if token_valid[i] == 0:
            risk += 2
        if suspicious_ip[i] == 1:
            risk += 1
        if oauth_anomaly[i] == 1:
            risk += 2
        if rate_exceeded[i] == 1:
            risk += 1
        if token_reuse[i] == 1:
            risk += 2
        risk_level.append(risk)
        decision.append("BLOCK" if risk >= 3 else "ALLOW")

    # Создание DataFrame
    data = list(zip(
        range(1, n+1),
        external_services,
        requests_count,
        token_valid,
        suspicious_ip,
        oauth_anomaly,
        rate_exceeded,
        token_reuse,
        risk_level,
        decision
    ))

    df = pd.DataFrame(data, columns=[
        "ID", "Сторонний сервис", "Запросы", "Токен валиден",
        "Подозрит. IP", "OAuth-аномалия", "Превышение частоты",
        "Повтор токена", "Риск НСД", "Решение"
    ])

    # Статистика решений
    stats = df["Решение"].value_counts().to_dict()

    # Преобразование таблицы в HTML
    table_html = df.to_html(classes='table table-striped table-bordered', index=False)

    # ==================================================
    # ГЕНЕРАЦИЯ ГРАФИКОВ
    # ==================================================

    graphs = {}

    # 1. Линейный график – количество запросов по сервисам
    plt.figure(figsize=(12, 6))
    plt.plot(df["ID"], df["Запросы"], marker='o', linestyle='-', color='blue', linewidth=2, markersize=8)
    plt.title("Запросы к сторонним сервисам", fontsize=14, fontweight='bold')
    plt.xlabel("ID сервиса", fontsize=12)
    plt.ylabel("Количество запросов", fontsize=12)
    plt.grid(True, alpha=0.3)
    plt.xticks(df["ID"])
    graphs['requests_chart'] = generate_chart_base64()

    # 2. Линейный график – уровень риска НСД
    plt.figure(figsize=(12, 6))
    plt.plot(df["ID"], df["Риск НСД"], marker='s', linestyle='-', color='red', linewidth=2, markersize=8)
    plt.title("Уровень риска несанкционированного доступа", fontsize=14, fontweight='bold')
    plt.xlabel("ID сервиса", fontsize=12)
    plt.ylabel("Риск (баллы)", fontsize=12)
    plt.grid(True, alpha=0.3)
    plt.xticks(df["ID"])
    plt.axhline(y=3, color='orange', linestyle='--', linewidth=2, label='Порог блокировки (3)')
    plt.legend()
    graphs['risk_chart'] = generate_chart_base64()

    # 3. Круговая диаграмма решений
    plt.figure(figsize=(10, 8))
    decision_counts = df["Решение"].value_counts()
    labels = ["Разрешить (ALLOW)", "Заблокировать (BLOCK)"]
    sizes = [decision_counts.get("ALLOW", 0), decision_counts.get("BLOCK", 0)]
    colors = ['#66b3ff', '#ff6666']
    explode = (0.05, 0.1)
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90,
            shadow=True, explode=explode, colors=colors, textprops={'fontsize': 14})
    plt.title("Распределение решений контейнера", fontsize=14, fontweight='bold')
    graphs['pie_chart'] = generate_chart_base64()

    # 4. Гистограмма – риск по сервисам
    plt.figure(figsize=(12, 6))
    bar_colors = ['red' if r >= 3 else 'green' for r in df["Риск НСД"]]
    plt.bar(df["ID"], df["Риск НСД"], color=bar_colors, edgecolor='black')
    plt.title("Риск НСД для каждого стороннего сервиса", fontsize=14, fontweight='bold')
    plt.xlabel("ID сервиса", fontsize=12)
    plt.ylabel("Уровень риска", fontsize=12)
    plt.xticks(df["ID"])
    plt.axhline(y=3, color='orange', linestyle='--', linewidth=2, label='Порог блокировки (3)')
    plt.legend()
    plt.grid(axis='y', alpha=0.3)
    graphs['risk_bars'] = generate_chart_base64()

    # 5. Суммарные срабатывания факторов риска
    plt.figure(figsize=(12, 6))
    risk_factors = {
        "Токен невалиден": n - sum(token_valid),
        "Подозрительный IP": sum(suspicious_ip),
        "OAuth-аномалия": sum(oauth_anomaly),
        "Превышение частоты": sum(rate_exceeded),
        "Повтор токена": sum(token_reuse)
    }

    factors_df = pd.DataFrame(list(risk_factors.items()), columns=['Фактор риска', 'Количество'])
    colors_bar = ['#ff6b6b', '#ffa500', '#9b59b6', '#3498db', '#e74c3c']
    plt.bar(factors_df['Фактор риска'], factors_df['Количество'], color=colors_bar, edgecolor='black')
    plt.title("Суммарные срабатывания факторов риска по всем сервисам", fontsize=14, fontweight='bold')
    plt.ylabel("Количество случаев", fontsize=12)
    plt.xticks(rotation=45, ha='right')
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    graphs['risk_factors_sum'] = generate_chart_base64()

    # 6. Сравнительный график (запросы и риск)
    fig, ax1 = plt.subplots(figsize=(12, 6))

    ax1.set_xlabel('ID сервиса', fontsize=12)
    ax1.set_ylabel('Запросы', color='blue', fontsize=12)
    ax1.plot(df["ID"], df["Запросы"], marker='o', color='blue', linewidth=2, markersize=8, label='Запросы')
    ax1.tick_params(axis='y', labelcolor='blue')
    ax1.set_xticks(df["ID"])

    ax2 = ax1.twinx()
    ax2.set_ylabel('Риск НСД', color='red', fontsize=12)
    ax2.plot(df["ID"], df["Риск НСД"], marker='s', color='red', linewidth=2, markersize=8, label='Риск')
    ax2.tick_params(axis='y', labelcolor='red')
    ax2.axhline(y=3, color='orange', linestyle='--', linewidth=2, alpha=0.7)

    plt.title("Сравнение запросов и уровня риска", fontsize=14, fontweight='bold')
    fig.tight_layout()
    graphs['comparison_chart'] = generate_chart_base64()

    # Передаём все данные в шаблон
    context = {
        'table_html': table_html,
        'stats': stats,
        'graphs': graphs,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    return render(request, 'accesssecurity/results.html', context)