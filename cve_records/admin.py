from django.contrib import admin
from.models import CVEHistory, ImportCheckpoint
# Register your models here.
admin.site.register(CVEHistory)
admin.site.register(ImportCheckpoint)
    