from django.db import models

class CVEHistory(models.Model):
    cveId = models.CharField(max_length=200, db_index=True)
    eventName = models.CharField(max_length=200, null=True, blank=True, db_index=True)
    cveChangeId = models.CharField(max_length=200, unique=True)
    sourceIdentifier = models.CharField(max_length=200, null=True, blank=True, db_index=True)
    created = models.DateTimeField(null=True, blank=True, db_index=True)
    details = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"{self.cveId} - {self.eventName}"


class ImportCheckpoint(models.Model):
    name = models.CharField(max_length=100, unique=True)
    next_index = models.BigIntegerField(default=0)
    total = models.BigIntegerField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} - {self.next_index}"