import io
import json
from django.shortcuts import render
from django.db.models import Count
from django.http import StreamingHttpResponse
import csv
import datetime
from django.views.generic import ListView
from django_filters import FilterSet, CharFilter, DateFilter
from django.forms import DateInput
from .models import CVEHistory


class CVEHistoryFilter(FilterSet):
    cveId = CharFilter(field_name="cveId", lookup_expr="icontains", label="CVE ID")
    eventName = CharFilter(field_name="eventName", lookup_expr="icontains", label="Event Name")
    cveChangeId = CharFilter(field_name="cveChangeId", lookup_expr="icontains", label="CVE Change ID")
    sourceIdentifier = CharFilter(field_name="sourceIdentifier", lookup_expr="icontains", label="Source")
    created_after = DateFilter(field_name="created", lookup_expr="gte", label="Created From",
                               widget=DateInput(attrs={"type": "date"}))
    created_before = DateFilter(field_name="created", lookup_expr="lte", label="Created To",
                                widget=DateInput(attrs={"type": "date"}))

    class Meta:
        model = CVEHistory
        fields = ["cveId", "eventName", "cveChangeId", "sourceIdentifier", "created_after", "created_before"]


class CVEHistoryListView(ListView):
    model = CVEHistory
    template_name = "cve_records/cve_history_list.html"
    context_object_name = "records"
    paginate_by = 50
    ordering = ['-created']  

    def get_queryset(self):
        queryset = super().get_queryset()
        self.filter = CVEHistoryFilter(self.request.GET, queryset=queryset)
        queryset = self.filter.qs
        sort_by = self.request.GET.get('sort', '-created')
        if sort_by.startswith('-'):
            field = sort_by[1:]
        else:
            field = sort_by

        allowed = {'cveId', 'eventName', 'cveChangeId', 'sourceIdentifier', 'created'}
        if field in allowed:
            try:
                queryset = queryset.order_by(sort_by)
            except Exception:
                queryset = queryset.order_by('-created')
        else:
            queryset = queryset.order_by('-created')

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["filter"] = self.filter
        query = self.request.GET.copy()
        if 'page' in query:
            del query['page']
        context['query_params'] = query.urlencode()
        query_no_sort = query.copy()
        if 'sort' in query_no_sort:
            del query_no_sort['sort']
        context['query_params_no_sort'] = query_no_sort.urlencode()
        context['sort_by'] = self.request.GET.get('sort', '-created')
        context['sortable_fields'] = ['cveId', 'eventName', 'cveChangeId', 'sourceIdentifier', 'created']
        return context

def export_cve_history(request):
    queryset = CVEHistory.objects.all()
    try:
        filter_obj = CVEHistoryFilter(request.GET, queryset=queryset)
        records_qs = filter_obj.qs.values_list('cveId', 'eventName', 'cveChangeId', 'sourceIdentifier', 'created')
    except Exception:
        records_qs = queryset.values_list('cveId', 'eventName', 'cveChangeId', 'sourceIdentifier', 'created')

    

    def stream_rows():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["CVEID", "EventName", "CveChangeId", "SourceIdentifier", "Created Date"])
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)

        for row in records_qs.iterator(chunk_size=10000):
            cveid, event, changeid, source, created = row
            if isinstance(created, datetime.datetime):
                created = created.strftime("%Y-%m-%d %H:%M:%S")
            else:
                created = created or ""
            writer.writerow([cveid or "", event or "", changeid or "", source or "", created])
            data = buf.getvalue()
            yield data
            buf.seek(0)
            buf.truncate(0)

    filename = "cve_history.csv"
    response = StreamingHttpResponse(stream_rows(), content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def cve_history_chart(request):
    base_qs = CVEHistory.objects.all()
    try:
        filter_obj = CVEHistoryFilter(request.GET, queryset=base_qs)
        base_qs = filter_obj.qs
    except Exception:
        pass

    qs = base_qs.values('eventName').annotate(count=Count('id')).order_by('-count')

    data = []
    for row in qs:
        name = row.get('eventName') or '(empty)'
        data.append({'name': name, 'value': row.get('count', 0)})

   
    top_n = 10
    data = data[:top_n]
    pie_total = base_qs.count()
    palette = [
        '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#06b6d4', '#059669', '#fb923c', '#8b5cf6', '#ec4899', '#475569'
    ]
    for i, item in enumerate(data):
        value = item.get('value', 0)
        item['percentage'] = round((value / pie_total * 100) if pie_total else 0, 2)
        item['color'] = palette[i % len(palette)]

    context = {
        'pie_data_json': json.dumps(data),
        'pie_data': data,
        'pie_total': pie_total,
    }
    return render(request, 'cve_records/cve_history_chart.html', context)



