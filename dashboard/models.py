from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

# 1. USER PROFILES (For Role-Based Access Control)
class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('Admin', 'Admin'),
        ('Analyst', 'Security Analyst'),
        ('Employee', 'General Employee'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='Employee')
    department = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.role}"

# --- AUTOMATION SIGNALS (Place these at the top level) ---
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if hasattr(instance, 'userprofile'):
        instance.userprofile.save()

# 2. PHISHING SCAN HISTORY
class PhishingScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True) # Linked to analyst
    url = models.URLField(max_length=500)
    verdict = models.CharField(max_length=20) 
    confidence_score = models.FloatField()
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"URL Scan: {self.url[:30]}... ({self.verdict})"

# 3. NETWORK RECON HISTORY
class NetworkScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True) # Linked to analyst
    target_ip = models.GenericIPAddressField()
    status = models.CharField(max_length=10) 
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Network Scan: {self.target_ip} at {self.scanned_at}"

# 4. VULNERABILITY MODEL (Isolated via NetworkScan)
class Vulnerability(models.Model):
    SEVERITY_CHOICES = [('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High'), ('Critical', 'Critical')]
    parent_scan = models.ForeignKey(NetworkScan, on_delete=models.CASCADE, related_name='vulnerabilities', null=True)
    title = models.CharField(max_length=200)
    port = models.IntegerField(null=True, blank=True)
    service = models.CharField(max_length=50, blank=True)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='Low')
    discovered_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    remediation_steps = models.TextField(blank=True)

    def __str__(self):
        return f"{self.title} - {self.severity}"