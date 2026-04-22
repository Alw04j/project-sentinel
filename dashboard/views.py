import joblib, os, re, socket
from django.shortcuts import redirect, render
from django.conf import settings
from django.contrib import messages
from dashboard.services.train_arff import MODEL_PATH
from .models import Vulnerability, PhishingScan, NetworkScan 
from .services.extractor import extract_features
from .services.scanner import scan_network,fix_smb_vulnerability
from urllib.parse import urlparse
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.decorators import login_required

@login_required
def home_dashboard(request):
    # 1. TOTAL SCANS: Sum of URL and Network scan actions
    p_count = PhishingScan.objects.filter(user=request.user).count()
    n_count = NetworkScan.objects.filter(user=request.user).count()
    total_scans = p_count + n_count

    # 2. HIGH RISK: Count actual vulnerability records marked High/Critical
    # We look specifically at the Vulnerability table
    high_risk_vulns = Vulnerability.objects.filter(
        parent_scan__user=request.user, 
        severity__in=['High', 'Critical']
    ).count()

    # 3. Table Data: Latest vulnerabilities for the dashboard
    latest_threats = Vulnerability.objects.filter(
        parent_scan__user=request.user
    ).order_by('-discovered_at')[:5]

    context = {
        'threats': latest_threats,
        'total_count': total_scans, # This should be 16
        'high_risk_count': high_risk_vulns, # This will now show the actual count (e.g., 2)
        'safe_count': PhishingScan.objects.filter(user=request.user, verdict='Safe').count(),
        'malicious_count': PhishingScan.objects.filter(user=request.user, verdict='Malicious').count(),
        'ip_hint': request.session.get('ip_hint', '127.0.0.1'),
        'result': request.session.pop('scan_result', None), 
    }
    return render(request, 'index.html', context)

def signup_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('home')
    else:
        form = UserCreationForm()
    return render(request, 'signup.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('home')
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('login')

try:
    PHISH_MODEL = joblib.load(MODEL_PATH)
    print("Sentinel AI Model Loaded Successfully.")
except Exception as e:
    print(f"Error loading AI model: {e}")
    PHISH_MODEL = None
@login_required
def phish_scan(request):
    result = None
    if request.method == 'POST':
        # --- 1. GET THE RAW INPUT ---
        url = request.POST.get('url', '').strip().lower()
        
        # --- 2. CLEANING & PARSING (The "Gatekeeper") ---
        # Ensure it has a protocol so urlparse works correctly
        url_to_parse = url if url.startswith(('http://', 'https://')) else 'http://' + url
        parsed = urlparse(url_to_parse)
        
        # Get the domain part (e.g., 'google.com')
        hostname = parsed.netloc.split(':')[0]
        
        # This part catches the '?' if it's in the domain (like 'asdf.qwer?')
        raw_domain_area = url.replace('http://', '').replace('https://', '').split('/')[0]

        # --- 3. STRICT VALIDATION CHECK ---
        is_valid = (
            '.' in hostname and               # Must have at least one dot
            '?' not in raw_domain_area and    # No '?' allowed in the domain name
            not hostname.startswith('.') and  # Can't start with a dot
            len(hostname.split('.')[-1]) >= 2 # TLD must be real (2+ letters)
        )

        # --- 4. THE DECISION GATE ---
        if not is_valid:
            request.session['scan_result'] = {
                'url': url,
                'status': "Invalid",
                'class': "warning",
                'message': "Sentinel doesn't scan gibberish. Use a valid domain or IP."
            }
        else:
            # --- 2. FEATURE EXTRACTION ---
            url_features = extract_features(url)
            
            # --- 3. SECURITY GUARD (HEURISTICS) ---
            # Rule A: IP Threat (Standard or Hex)
            is_ip_threat = (url_features[0] == -1)
            
            # Rule B: Keyword Spoofing (Keywords + Hyphens)
            keywords = ['login', 'verify', 'update', 'bank', 'facebook', 'google', 'paypal']
            has_keywords = any(word in url for word in keywords)
            is_hyphenated = (url_features[5] == -1)
            is_keyword_threat = has_keywords and is_hyphenated

            # Rule C: Unsafe Shortener (Shortener + No HTTPS)
            no_https = (url_features[7] == -1)
            is_shortener_threat = (url_features[2] == -1 and no_https)

            # Rule D: Subdomain Spam (Multiple dots + Keywords)
            is_subdomain_threat = has_keywords and (url_features[6] == -1)
            
            # Rule E: Punycode (Homograph Attack)
            is_punycode = 'xn--' in url

            # --- 4. AI PREDICTION ---
            model = PHISH_MODEL # Use the preloaded model
            prediction = int(model.predict([url_features])[0])
            probabilities = model.predict_proba([url_features])[0]
            confidence = max(probabilities) * 100

            # --- 5. FINAL VERDICT ---
            # If any Hard Rule is hit OR the AI predicts Malicious
            any_guard_hit = is_ip_threat or is_keyword_threat or is_shortener_threat or is_subdomain_threat or is_punycode
            
            if any_guard_hit or prediction == -1:
                status, s_class, score = "Malicious", "danger", 99.9 if any_guard_hit else round(confidence, 2)
            else:
                status, s_class, score = "Safe", "success", round(confidence, 2)

            # ==========================================================
            # ✅ SAVE TO DB (Inside the 'else' so variables are defined)
            # ==========================================================
            PhishingScan.objects.create(
                user=request.user if request.user.is_authenticated else None,
                url=url,
                verdict=status,
                confidence_score=score
            )
            request.session['scan_result'] = {
                'url': url, 'status': status, 'class': s_class, 'score': score
            }
        return redirect('home')
    return redirect('home')

from .services.scanner import scan_network

@login_required
def network_scanner_view(request):
    # --- GET IP HINT LOGIC ---
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Takes 192.168.1.5 and turns it into 192.168.1.0/24
        ip_hint = f"{local_ip.rsplit('.', 1)[0]}.0/24" 
    except:
        ip_hint = "127.0.0.1"

    results, error, target = None, None, ""
    if request.method == 'POST':
        target = request.POST.get("target_ip", "").strip()
        if target:
            data = scan_network(target)
            if isinstance(data, dict) and "error" in data:
                error = data["error"]
            else:
                results = data
                # --- MAJOR PROJECT UPGRADE: SAVE TO DB ---
                # 1. Save the main scan event
                scan_obj = NetworkScan.objects.create(
                    user=request.user if request.user.is_authenticated else None,
                    target_ip=target,
                    status='up' if data else 'down'
                )
                
                # 2. Loop through results and save each vulnerability
                for host in data:
                    for port in host['ports']:
                        Vulnerability.objects.create(
                            parent_scan=scan_obj,
                            title=f"Open Port {port['port']} ({port['service']})",
                            port=port['port'],
                            service=port['service'],
                            severity=port['severity'],
                            description=f"Automated recon found {port['service']} on {host['address']}.",
                            is_resolved=False
                        )
                
    return render(request, 'network_scanner.html', {
        'results': results,
        'ip_hint': ip_hint, # MUST pass this to the template
    })

@login_required
def scan_history(request):
    # 1. Isolate Phishing Logs (Everyone sees their own)
    url_history = PhishingScan.objects.filter(user=request.user).order_by('-scanned_at')
    
    # 2. Initialize Network Logs as empty
    net_history = []

    # 3. Secure Gatekeeper: Only fetch network logs for high-privilege roles
    # We use getattr() to safely check for the profile
    profile = getattr(request.user, 'userprofile', None)
    if profile and profile.role in ['Admin', 'Analyst']:
        # Admin/Analyst sees their own network intelligence
        net_history = NetworkScan.objects.filter(user=request.user).order_by('-scanned_at')

    return render(request, 'history.html', {
        'url_history': url_history,
        'net_history': net_history
    })

@login_required
def remediate_smb(request):
    if not request.user.is_staff:
        messages.error(request, "Access Denied: Administrative privileges required.")
        return redirect('home')
    # Call the netsh command function from your scanner.py
    status_message = fix_smb_vulnerability() # We only want the message part for the user
    
    if "SUCCESS" in status_message:
        messages.success(request, status_message)
    else:
        messages.error(request, status_message)
        
    return redirect('home')

@login_required
def vulnerability_report(request):
    # Fetch ALL vulnerabilities found by this analyst
    all_vulns = Vulnerability.objects.filter(parent_scan__user=request.user).order_by('title', '-discovered_at')

    return render(request, 'vulnerability_report.html', {
        'vulns': all_vulns
    })