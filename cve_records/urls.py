from django.urls import path
from .views import CVEHistoryListView, export_cve_history, cve_history_chart

app_name = 'cve_records'
urlpatterns = [
    path('', CVEHistoryListView.as_view(), name='cve_history_list'),
    path('export/', export_cve_history, name='cve_history_export'),
    path('chart/', cve_history_chart, name='cve_history_chart'),
]