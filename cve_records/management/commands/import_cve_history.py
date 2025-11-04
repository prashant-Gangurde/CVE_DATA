import time
import json
import hashlib
from django.db import transaction
from django.utils.dateparse import parse_datetime
from typing import List
import requests
from django.core.management.base import BaseCommand
from cve_records.models import CVEHistory, ImportCheckpoint


API_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"



class Command(BaseCommand):
    help = "Import CVE history from NVD CVE History API into the local database"

    def add_arguments(self, parser):
        parser.add_argument(
            "--page-size",
            type=int,
            default=5000,
            help="Number of results per page (max 5000)",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=1000,
            help="Number of records to insert in one transaction",
        )
        parser.add_argument(
            "--max-retries",
            dest="max_retries",
            type=int,
            default=3,
            help="Maximum number of retries for failed API requests",
        )
        parser.add_argument(
            "--checkpoint-name",
            dest="checkpoint_name",
            type=str,
            default="cve_history",
            help="Name of the checkpoint to track progress",
        )
        parser.add_argument(
            "--reset-checkpoint",
            dest="reset_checkpoint",
            action="store_true",
            help="Reset the checkpoint and start from beginning",
        )

    def handle(self, *args, **options):
        page_size: int = options["page_size"]
        batch_size: int = options["batch_size"]
        max_retries: int = options["max_retries"]
        checkpoint_name: str = options["checkpoint_name"]
        reset_checkpoint: bool = options["reset_checkpoint"]
        session = requests.Session()
        session.headers.update({"User-Agent": "cve-history-importer/1.0"})
        checkpoint, _ = ImportCheckpoint.objects.get_or_create(
            name=checkpoint_name,
            defaults={"next_index": 0}
        )

        if reset_checkpoint:
            checkpoint.next_index = 0
            checkpoint.total = None
            checkpoint.save()

        start = checkpoint.next_index
        total_results = checkpoint.total

        while True:
            params = {"startIndex": start, "resultsPerPage": page_size}
            self.stdout.write(f"Fetching records from startIndex={start}")
            for attempt in range(max_retries):
                try:
                    resp = session.get(API_URL, params=params, timeout=30)
                    resp.raise_for_status()
                    break
                except Exception as e:
                    if attempt == max_retries - 1:
                        self.stderr.write(
                            self.style.ERROR(f"Failed to fetch after {max_retries} attempts at index {start}: {e}")
                        )
                        raise
                    self.stdout.write(f"Attempt {attempt + 1} failed, retrying in 5s: {e}")
                    time.sleep(5 * (attempt + 1)) 

            data = resp.json()
            total_results = total_results or data.get("totalResults")
            if total_results and not checkpoint.total:
                checkpoint.total = total_results
                checkpoint.save()

            records = data.get("cveChanges", [])
            if not records:
                self.stdout.write(f"No records found at startIndex={start}. Stopping.")
                break

            objs: List[CVEHistory] = []
            for rec in records:
                change = rec.get("change", {})
                
                cve_id = change.get("cveId")
                event_name = change.get("eventName")
                cve_change_id = change.get("cveChangeId")
                source_identifier = change.get("sourceIdentifier")

                created_raw = change.get("created")
                created_dt = None
                if created_raw:
                    created_dt = parse_datetime(created_raw)
                    if created_dt is None and "." in created_raw:
                        created_dt = parse_datetime(created_raw.split(".")[0])

                details = change.get("details")
                if not isinstance(details, (list, dict)):
                    details = None

                if not cve_change_id:
                    try:
                        raw_str = json.dumps(change, sort_keys=True)
                    except Exception:
                        raw_str = str(change)
                    cve_change_id = hashlib.sha1(raw_str.encode("utf-8")).hexdigest()

                objs.append(
                    CVEHistory(
                        cveId=cve_id or "unknown",
                        eventName=event_name,
                        cveChangeId=cve_change_id,
                        sourceIdentifier=source_identifier,
                        created=created_dt,
                        details=details,
                    )
                )

            created = 0
            try:
                with transaction.atomic():
                    for i in range(0, len(objs), batch_size):
                        chunk = objs[i : i + batch_size]
                        chunk_ids = [o.cveChangeId for o in chunk if o.cveChangeId]

                        existing = set()
                        if chunk_ids:
                            existing = set(
                                CVEHistory.objects.filter(cveChangeId__in=chunk_ids)
                                .values_list("cveChangeId", flat=True)
                            )

                        to_create = [o for o in chunk if o.cveChangeId not in existing]
                        if to_create:
                            CVEHistory.objects.bulk_create(to_create)
                            created += len(to_create)

            except Exception as e:
                self.stderr.write(
                    self.style.ERROR(f"Database insert failed  start {start}: {e}")
                )
                raise

            start += len(records)
            checkpoint.next_index = start
            checkpoint.save()

            self.stdout.write(
                self.style.SUCCESS(
                    f"Imported {created} new records (progress: {start}/{total_results or 'unknown'})"
                )
            )

            if isinstance(total_results, int) and start >= total_results:
                self.stdout.write(self.style.SUCCESS("All records done"))
                break

            time.sleep(0.2)

        self.stdout.write(self.style.SUCCESS("All DATA Save successfully."))
