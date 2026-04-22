from django.contrib import admin
from .models import Vulnerability, PhishingScan, NetworkScan, UserProfile

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('title', 'severity', 'is_resolved', 'discovered_at')
    list_filter = ('severity', 'is_resolved')

admin.site.register(PhishingScan)
admin.site.register(NetworkScan)
admin.site.register(UserProfile)