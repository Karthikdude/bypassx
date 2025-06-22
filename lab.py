from flask import Flask, request, jsonify, redirect, make_response, render_template_string
import os
import re
import urllib.parse
import logging
from datetime import datetime

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Track bypass attempts for analysis
bypass_attempts = []

def log_attempt(endpoint, technique, success, status_code, details=""):
    """Log bypass attempts for analysis"""
    attempt = {
        'timestamp': datetime.now().isoformat(),
        'endpoint': endpoint,
        'technique': technique,
        'success': success,
        'status_code': status_code,
        'method': request.method,
        'path': request.path,
        'headers': dict(request.headers),
        'args': dict(request.args),
        'details': details
    }
    bypass_attempts.append(attempt)
    logger.info(f"[{technique}] {endpoint} - {'SUCCESS' if success else 'FAILED'} ({status_code})")

@app.route('/')
def index():
    """Main page with testing information"""
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>BypassX Testing Lab</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .endpoint { background: #f5f5f5; padding: 15px; margin: 10px 0; border-radius: 5px; }
            .success { color: #2e7d32; }
            .failed { color: #c62828; }
            .technique { font-weight: bold; color: #1565c0; }
        </style>
    </head>
    <body>
        <h1>BypassX Testing Lab</h1>
        <p>This lab provides various protected endpoints to test bypass techniques.</p>
        
        <h2>Protected Endpoints:</h2>
        <div class="endpoint">
            <strong>/admin</strong> - Main admin panel (vulnerable to multiple techniques)
        </div>
        <div class="endpoint">
            <strong>/api/admin</strong> - API admin endpoint (vulnerable to path techniques)
        </div>
        <div class="endpoint">
            <strong>/secure</strong> - Secure area (vulnerable to header techniques)
        </div>
        <div class="endpoint">
            <strong>/internal</strong> - Internal access (vulnerable to IP spoofing)
        </div>
        <div class="endpoint">
            <strong>/debug</strong> - Debug endpoint (vulnerable to method tampering)
        </div>
        <div class="endpoint">
            <strong>/waf</strong> - Modern WAF endpoint (Cloudflare-style protection)
        </div>
        <div class="endpoint">
            <strong>/cdn</strong> - CDN bypass endpoint (Origin IP & cache techniques)
        </div>
        <div class="endpoint">
            <strong>/api/v2/admin</strong> - API v2 with JWT & GraphQL vulnerabilities
        </div>
        <div class="endpoint">
            <strong>/microservice</strong> - Container & service mesh bypasses
        </div>
        <div class="endpoint">
            <strong>/ml-protected</strong> - ML/AI evasion techniques
        </div>
        <div class="endpoint">
            <strong>/advanced</strong> - Unicode & encoding bypass testing
        </div>
        
        <h2>Recent Bypass Attempts: <span id="total">{{ total_attempts }}</span></h2>
        <div id="attempts">
            {% for attempt in recent_attempts %}
            <div class="endpoint">
                <span class="technique">{{ attempt.technique }}</span> - 
                <span class="{{ 'success' if attempt.success else 'failed' }}">
                    {{ 'SUCCESS' if attempt.success else 'FAILED' }}
                </span>
                ({{ attempt.status_code }}) - {{ attempt.endpoint }} via {{ attempt.method }}
                <br><small>{{ attempt.timestamp }}</small>
            </div>
            {% endfor %}
        </div>
        
        <p><a href="/stats">View Full Statistics</a></p>
    </body>
    </html>
    """
    
    recent_attempts = bypass_attempts[-20:] if bypass_attempts else []
    return render_template_string(html_template, 
                                recent_attempts=reversed(recent_attempts),
                                total_attempts=len(bypass_attempts))

@app.route('/stats')
def stats():
    """Statistics page showing all bypass attempts"""
    success_count = sum(1 for attempt in bypass_attempts if attempt['success'])
    total_count = len(bypass_attempts)
    
    # Group by technique
    technique_stats = {}
    for attempt in bypass_attempts:
        technique = attempt['technique']
        if technique not in technique_stats:
            technique_stats[technique] = {'total': 0, 'success': 0}
        technique_stats[technique]['total'] += 1
        if attempt['success']:
            technique_stats[technique]['success'] += 1
    
    return jsonify({
        'total_attempts': total_count,
        'successful_bypasses': success_count,
        'success_rate': round((success_count / total_count * 100) if total_count > 0 else 0, 2),
        'technique_breakdown': technique_stats,
        'all_attempts': bypass_attempts
    })

# ================================
# MAIN ADMIN ENDPOINT
# ================================
@app.route('/admin', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE'])
@app.route('/admin/', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE'])
@app.route('/admin/.', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE'])
def admin_panel():
    """Main admin panel with comprehensive bypass vulnerabilities"""
    
    # Default 403 response
    default_response = make_response(jsonify(message="Access Denied: Forbidden"), 403)
    
    # === BASIC BYPASS TECHNIQUES ===
    
    # 1. HTTP Method Tampering - OPTIONS allowed
    if request.method == 'OPTIONS':
        log_attempt('/admin', 'HTTP_METHOD_OPTIONS', True, 200)
        resp = make_response(jsonify(message="Options allowed for admin"), 200)
        resp.headers['Allow'] = 'GET, POST, OPTIONS'
        return resp
    
    # X-HTTP-Method-Override
    if request.headers.get('X-HTTP-Method-Override') == 'GET':
        log_attempt('/admin', 'X_HTTP_METHOD_OVERRIDE_GET', True, 200)
        return make_response(jsonify(message="X-HTTP-Method-Override bypass success!"), 200)
    
    # 2. Path/URL Obfuscation - Trailing slash bypass
    if request.path == '/admin/':
        log_attempt('/admin', 'TRAILING_SLASH', True, 200)
        return make_response(jsonify(message="Trailing slash bypass success!"), 200)
    
    # Trailing dot bypass
    if request.path == '/admin/.':
        log_attempt('/admin', 'TRAILING_DOT', True, 200)
        return make_response(jsonify(message="Trailing dot bypass success!"), 200)
    
    # Case manipulation bypass
    if request.path.lower() != request.path and 'admin' in request.path.lower():
        log_attempt('/admin', 'CASE_MANIPULATION', True, 200)
        return make_response(jsonify(message="Case manipulation bypass success!"), 200)
    
    # 3. Header Manipulation - IP Spoofing
    spoofing_headers = ['X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP', 'X-Remote-IP']
    for header in spoofing_headers:
        if request.headers.get(header) == '127.0.0.1':
            log_attempt('/admin', f'IP_SPOOF_{header.replace("-", "_")}', True, 200)
            return make_response(jsonify(message=f"IP spoofing bypass via {header} success!"), 200)
    
    # Referer bypass
    if request.headers.get('Referer') == 'https://google.com':
        log_attempt('/admin', 'REFERER_MANIPULATION_0', True, 200)
        return make_response(jsonify(message="Referer bypass success!"), 200)
    
    # User-Agent bypass (Googlebot)
    if 'Googlebot' in request.headers.get('User-Agent', ''):
        log_attempt('/admin', 'USER_AGENT_GOOGLEBOT', True, 200)
        return make_response(jsonify(message="Googlebot User-Agent bypass success!"), 200)
    
    # 4. Host Header bypass
    if request.headers.get('Host') == 'localhost':
        log_attempt('/admin', 'HOST_HEADER_localhost', True, 200)
        return make_response(jsonify(message="Host header bypass success!"), 200)
    
    # 5. Forwarded header bypass
    if 'for=127.0.0.1' in request.headers.get('Forwarded', ''):
        log_attempt('/admin', 'FORWARDED_Forwarded', True, 200)
        return make_response(jsonify(message="Forwarded header bypass success!"), 200)
    
    # Log failed attempt
    log_attempt('/admin', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# API ADMIN ENDPOINT  
# ================================
@app.route('/api/admin', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
def api_admin():
    """API admin endpoint vulnerable to path manipulation"""
    
    # Default 403
    default_response = make_response(jsonify(message="API Access Denied"), 403)
    
    # Path traversal bypass
    if '/../admin' in request.full_path or '/..%2fadmin' in request.full_path:
        log_attempt('/api/admin', 'PATH_TRAVERSAL', True, 200)
        return make_response(jsonify(message="Path traversal bypass success!"), 200)
    
    # Double slash bypass
    if '/api//admin' in request.path or '/api/%2f/admin' in request.full_path:
        log_attempt('/api/admin', 'DOUBLE_SLASH', True, 200)
        return make_response(jsonify(message="Double slash bypass success!"), 200)
    
    # Content-Type bypass
    if request.headers.get('Content-Type') == 'application/xml':
        log_attempt('/api/admin', 'CONTENT_TYPE_application_xml', True, 200)
        return make_response(jsonify(message="Content-Type bypass success!"), 200)
    
    log_attempt('/api/admin', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# SECURE ENDPOINT
# ================================
@app.route('/secure', methods=['GET', 'POST', 'HEAD', 'OPTIONS'])
def secure_area():
    """Secure area vulnerable to authentication bypasses"""
    
    default_response = make_response(jsonify(message="Secure Area - Access Denied"), 403)
    
    # Basic auth bypass with dummy credentials
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Basic '):
        # In real implementation, this should decode base64
        if 'admin:password' in auth_header or 'test:test' in auth_header:
            log_attempt('/secure', 'BASIC_AUTH_DUMMY', True, 200)
            return make_response(jsonify(message="Basic auth bypass success!"), 200)
    
    # Bearer token bypass
    if auth_header.startswith('Bearer invalid_token'):
        log_attempt('/secure', 'BEARER_TOKEN_0', True, 200)
        return make_response(jsonify(message="Invalid bearer token bypass success!"), 200)
    
    # WebSocket upgrade bypass
    if (request.headers.get('Upgrade') == 'websocket' and 
        request.headers.get('Connection') == 'Upgrade'):
        log_attempt('/secure', 'WEBSOCKET_UPGRADE', True, 200)
        return make_response(jsonify(message="WebSocket upgrade bypass success!"), 200)
    
    log_attempt('/secure', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# INTERNAL ENDPOINT
# ================================
@app.route('/internal', methods=['GET', 'POST', 'HEAD'])
def internal_access():
    """Internal endpoint vulnerable to header pollution"""
    
    default_response = make_response(jsonify(message="Internal Access - Forbidden"), 403)
    
    # Header pollution bypass
    xff_header = request.headers.get('X-Forwarded-For', '')
    if 'evil.com, 127.0.0.1' in xff_header:
        log_attempt('/internal', 'HEADER_POLLUTION_XFF', True, 200)
        return make_response(jsonify(message="Header pollution bypass success!"), 200)
    
    # X-Forwarded-Host bypass
    xfh_header = request.headers.get('X-Forwarded-Host', '')
    if 'internal.local' in xfh_header:
        log_attempt('/internal', 'HEADER_POLLUTION_XFH', True, 200)
        return make_response(jsonify(message="X-Forwarded-Host bypass success!"), 200)
    
    log_attempt('/internal', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# DEBUG ENDPOINT
# ================================
@app.route('/debug', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE'])
def debug_endpoint():
    """Debug endpoint vulnerable to various advanced techniques"""
    
    default_response = make_response(jsonify(message="Debug Access - Forbidden"), 403)
    
    # Verb tunneling bypass
    if request.args.get('_method') == 'GET':
        log_attempt('/debug', 'VERB_TUNNELING_0', True, 200)
        return make_response(jsonify(message="Verb tunneling bypass success!"), 200)
    
    # Fragment bypass (simulated by checking URL args)
    if request.args.get('redirect'):
        log_attempt('/debug', 'FRAGMENT_1', True, 200)
        return make_response(jsonify(message="Fragment redirect bypass success!"), 200)
    
    # File extension spoofing
    if request.path.endswith('.json'):
        log_attempt('/debug', 'EXTENSION_SPOOF__json', True, 200)
        return make_response(jsonify(message="Extension spoofing bypass success!"), 200)
    
    log_attempt('/debug', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# MODERN WAF/SECURITY BYPASS ENDPOINTS
# ================================
@app.route('/waf', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
def modern_waf_endpoint():
    """Modern WAF endpoint with advanced blocking and evasion techniques"""
    
    default_response = make_response(jsonify(message="WAF Blocked - Access Denied", waf_id="CF-001"), 403)
    
    # Cloudflare-style blocking with rate limiting simulation
    user_agent = request.headers.get('User-Agent', '')
    if 'curl' in user_agent.lower() or 'wget' in user_agent.lower():
        if not request.headers.get('CF-Connecting-IP'):
            log_attempt('/waf', 'WAF_BLOCK_AUTOMATED_TOOLS', False, 403)
            return make_response(jsonify(message="Automated tool detected", waf_rule="AT-001"), 403)
    
    # CF-Connecting-IP bypass
    if request.headers.get('CF-Connecting-IP') == '127.0.0.1':
        log_attempt('/waf', 'CF_CONNECTING_IP_BYPASS', True, 200)
        return make_response(jsonify(message="Cloudflare IP bypass success!"), 200)
    
    # Cache deception with X-Forwarded-Host
    if request.headers.get('X-Forwarded-Host') == 'cdn.example.com':
        log_attempt('/waf', 'CACHE_DECEPTION_XFH', True, 200)
        return make_response(jsonify(message="Cache deception bypass success!"), 200)
    
    # HTTP/2 pseudo-header bypass simulation
    if request.headers.get(':authority') == 'internal.service':
        log_attempt('/waf', 'HTTP2_AUTHORITY_BYPASS', True, 200)
        return make_response(jsonify(message="HTTP/2 authority bypass success!"), 200)
    
    # Request smuggling simulation via Transfer-Encoding
    if 'chunked' in request.headers.get('Transfer-Encoding', '').lower():
        if request.headers.get('Content-Length') == '0':
            log_attempt('/waf', 'REQUEST_SMUGGLING_TE_CL', True, 200)
            return make_response(jsonify(message="Request smuggling bypass success!"), 200)
    
    log_attempt('/waf', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/cdn', methods=['GET', 'POST', 'HEAD', 'OPTIONS'])
def cdn_bypass_endpoint():
    """CDN-specific bypass techniques"""
    
    default_response = make_response(jsonify(message="CDN Protected - Access Denied"), 403)
    
    # Origin IP bypass simulation
    if request.headers.get('X-Originating-IP') == '1.2.3.4':
        log_attempt('/cdn', 'ORIGIN_IP_BYPASS', True, 200)
        return make_response(jsonify(message="Origin IP bypass success!"), 200)
    
    # Cache key poisoning via X-Forwarded-Scheme
    if request.headers.get('X-Forwarded-Scheme') == 'internal':
        log_attempt('/cdn', 'CACHE_KEY_POISONING', True, 200)
        return make_response(jsonify(message="Cache key poisoning bypass success!"), 200)
    
    # Edge case: X-Edge-Location header
    if request.headers.get('X-Edge-Location'):
        log_attempt('/cdn', 'EDGE_LOCATION_BYPASS', True, 200)
        return make_response(jsonify(message="Edge location bypass success!"), 200)
    
    log_attempt('/cdn', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/api/v2/admin', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def api_v2_endpoint():
    """API v2 with modern authentication bypasses"""
    
    default_response = make_response(jsonify(message="API v2 Access Denied", error_code="AUTH_002"), 401)
    
    # JWT bypass with "none" algorithm
    auth_header = request.headers.get('Authorization', '')
    if 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0' in auth_header:
        log_attempt('/api/v2/admin', 'JWT_NONE_ALGORITHM', True, 200)
        return make_response(jsonify(message="JWT none algorithm bypass success!"), 200)
    
    # GraphQL introspection bypass
    if request.json and request.json.get('query', '').startswith('query IntrospectionQuery'):
        log_attempt('/api/v2/admin', 'GRAPHQL_INTROSPECTION', True, 200)
        return make_response(jsonify(message="GraphQL introspection bypass success!"), 200)
    
    # API versioning bypass via Accept header
    if 'application/vnd.api.v1+json' in request.headers.get('Accept', ''):
        log_attempt('/api/v2/admin', 'API_VERSION_DOWNGRADE', True, 200)
        return make_response(jsonify(message="API version downgrade bypass success!"), 200)
    
    # CORS preflight bypass
    if request.method == 'OPTIONS' and request.headers.get('Access-Control-Request-Method'):
        log_attempt('/api/v2/admin', 'CORS_PREFLIGHT_BYPASS', True, 200)
        resp = make_response(jsonify(message="CORS preflight bypass success!"), 200)
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
        return resp
    
    log_attempt('/api/v2/admin', 'DEFAULT_ACCESS', False, 401)
    return default_response

@app.route('/microservice', methods=['GET', 'POST'])
def microservice_endpoint():
    """Microservice with container and service mesh bypasses"""
    
    default_response = make_response(jsonify(message="Microservice Access Denied"), 403)
    
    # Istio service mesh bypass
    if request.headers.get('X-Envoy-Original-Path'):
        log_attempt('/microservice', 'ISTIO_ENVOY_BYPASS', True, 200)
        return make_response(jsonify(message="Istio/Envoy bypass success!"), 200)
    
    # Kubernetes internal service bypass
    if request.headers.get('X-Kubernetes-Service-Account'):
        log_attempt('/microservice', 'K8S_SERVICE_ACCOUNT', True, 200)
        return make_response(jsonify(message="Kubernetes service account bypass success!"), 200)
    
    # Docker container escape simulation
    container_id = request.headers.get('X-Container-Id', '')
    if container_id and 'privileged' in container_id:
        log_attempt('/microservice', 'CONTAINER_ESCAPE', True, 200)
        return make_response(jsonify(message="Container escape bypass success!"), 200)
    
    log_attempt('/microservice', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/ml-protected', methods=['GET', 'POST'])
def ml_protected_endpoint():
    """ML/AI-based protection system with evasion techniques"""
    
    default_response = make_response(jsonify(message="ML Protection Active - Access Denied", confidence=0.95), 403)
    
    # Adversarial input to confuse ML model
    user_agent = request.headers.get('User-Agent', '')
    if 'Mozilla/5.0 (compatible; MSIE 6.0; Windows 98; Win 9x 4.90)' in user_agent:
        # Old browser signature to evade modern ML detection
        log_attempt('/ml-protected', 'ML_EVASION_OLD_BROWSER', True, 200)
        return make_response(jsonify(message="ML evasion via old browser signature success!"), 200)
    
    # Timing attack simulation
    if request.headers.get('X-Timing-Attack') == 'slow':
        import time
        time.sleep(0.1)  # Simulate slow processing
        log_attempt('/ml-protected', 'TIMING_ATTACK_BYPASS', True, 200)
        return make_response(jsonify(message="Timing attack bypass success!"), 200)
    
    # Feature poisoning via unusual header combination
    if (request.headers.get('Accept-Language') == 'xx-XX' and 
        request.headers.get('Accept-Encoding') == 'identity' and
        request.headers.get('Connection') == 'close'):
        log_attempt('/ml-protected', 'ML_FEATURE_POISONING', True, 200)
        return make_response(jsonify(message="ML feature poisoning bypass success!"), 200)
    
    log_attempt('/ml-protected', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/advanced', methods=['GET', 'POST'])
def advanced_endpoint():
    """Endpoint for testing advanced bypass techniques"""
    
    default_response = make_response(jsonify(message="Advanced Access - Forbidden"), 403)
    
    # Unicode bypass (check for Cyrillic characters)
    if 'admіn' in request.path:  # Contains Cyrillic і
        log_attempt('/advanced', 'UNICODE_VARIATION_0', True, 200)
        return make_response(jsonify(message="Unicode bypass success!"), 200)
    
    # Double URL decode (simulated)
    if '%252f' in request.full_path:
        log_attempt('/advanced', 'DOUBLE_DECODE_0', True, 200)
        return make_response(jsonify(message="Double URL decode bypass success!"), 200)
    
    # Path confusion
    if '/%2e' in request.full_path:
        log_attempt('/advanced', 'PATH_CONFUSION_0', True, 200)
        return make_response(jsonify(message="Path confusion bypass success!"), 200)
    
    # CRLF injection
    if '%0d%0a' in request.full_path.lower() or '\r\n' in request.full_path:
        log_attempt('/advanced', 'CRLF_INJECTION', True, 200)
        return make_response(jsonify(message="CRLF injection bypass success!"), 200)
    
    log_attempt('/advanced', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# PROTOCOL & METHOD BYPASSES
# ================================
@app.route('/method-override', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
def method_override():
    """HTTP method override variations"""
    default_response = make_response(jsonify(message="Method Override - Access Denied"), 403)
    
    # X-HTTP-Method header
    if request.headers.get('X-HTTP-Method') == 'GET':
        log_attempt('/method-override', 'X_HTTP_METHOD', True, 200)
        return make_response(jsonify(message="X-HTTP-Method bypass success!"), 200)
    
    # X-Method-Override header
    if request.headers.get('X-Method-Override') == 'GET':
        log_attempt('/method-override', 'X_METHOD_OVERRIDE', True, 200)
        return make_response(jsonify(message="X-Method-Override bypass success!"), 200)
    
    # _method parameter
    if request.args.get('_method') == 'GET' or (request.form and request.form.get('_method') == 'GET'):
        log_attempt('/method-override', 'METHOD_PARAMETER', True, 200)
        return make_response(jsonify(message="Method parameter bypass success!"), 200)
    
    log_attempt('/method-override', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/http-version', methods=['GET', 'POST'])
def http_version():
    """HTTP version bypass attempts"""
    default_response = make_response(jsonify(message="HTTP Version - Access Denied"), 403)
    
    # HTTP/1.0 downgrade
    if request.environ.get('SERVER_PROTOCOL') == 'HTTP/1.0':
        log_attempt('/http-version', 'HTTP_1_0_DOWNGRADE', True, 200)
        return make_response(jsonify(message="HTTP/1.0 downgrade bypass success!"), 200)
    
    # HTTP/2 specific headers
    if request.headers.get('HTTP2-Settings'):
        log_attempt('/http-version', 'HTTP2_SETTINGS', True, 200)
        return make_response(jsonify(message="HTTP/2 settings bypass success!"), 200)
    
    log_attempt('/http-version', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/connect-method', methods=['CONNECT', 'GET', 'POST'])
def connect_method():
    """HTTP CONNECT method bypass"""
    default_response = make_response(jsonify(message="CONNECT Method - Access Denied"), 403)
    
    if request.method == 'CONNECT':
        log_attempt('/connect-method', 'CONNECT_METHOD', True, 200)
        return make_response(jsonify(message="CONNECT method bypass success!"), 200)
    
    # CONNECT via header
    if request.headers.get('X-HTTP-Method') == 'CONNECT':
        log_attempt('/connect-method', 'CONNECT_HEADER', True, 200)
        return make_response(jsonify(message="CONNECT header bypass success!"), 200)
    
    log_attempt('/connect-method', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# ADVANCED PATH MANIPULATION
# ================================
@app.route('/path-normalization', methods=['GET', 'POST'])
@app.route('/path-normalization/', methods=['GET', 'POST'])
@app.route('/path-normalization/../', methods=['GET', 'POST'])
@app.route('/path-normalization/./', methods=['GET', 'POST'])
@app.route('/path-normalization/.///', methods=['GET', 'POST'])
@app.route('/path-normalization%2e%2e/', methods=['GET', 'POST'])
@app.route('/path-normalization%2f', methods=['GET', 'POST'])
@app.route('/path-normalization%2e%2e', methods=['GET', 'POST'])
def path_normalization():
    """Path normalization bypasses"""
    default_response = make_response(jsonify(message="Path Normalization - Access Denied"), 403)
    
    # Check for path traversal patterns
    if '/../' in request.full_path or '/./' in request.full_path or '/.//' in request.full_path:
        log_attempt('/path-normalization', 'PATH_TRAVERSAL', True, 200)
        return make_response(jsonify(message="Path traversal bypass success!"), 200)
    
    # Encoded path traversal
    if '%2e%2e' in request.full_path or '%2f' in request.full_path:
        log_attempt('/path-normalization', 'ENCODED_TRAVERSAL', True, 200)
        return make_response(jsonify(message="Encoded traversal bypass success!"), 200)
    
    # Direct path variations - these should always succeed
    if request.path != '/path-normalization':
        log_attempt('/path-normalization', 'PATH_VARIATION', True, 200)
        return make_response(jsonify(message="Path variation bypass success!"), 200)
    
    log_attempt('/path-normalization', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/null-bytes', methods=['GET', 'POST'])
@app.route('/null-bytes%00', methods=['GET', 'POST']) 
@app.route('/null-bytes\x00', methods=['GET', 'POST'])
def null_bytes():
    """Null byte injection bypasses"""
    default_response = make_response(jsonify(message="Null Bytes - Access Denied"), 403)
    
    # Check all possible null byte representations
    if ('%00' in request.full_path or '\x00' in request.full_path or 
        request.path.endswith('%00') or request.path != '/null-bytes'):
        log_attempt('/null-bytes', 'NULL_BYTE_INJECTION', True, 200)
        return make_response(jsonify(message="Null byte injection bypass success!"), 200)
    
    log_attempt('/null-bytes', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/path-params', methods=['GET', 'POST'])
@app.route('/path-params;jsessionid=123', methods=['GET', 'POST'])
def path_params():
    """Semicolon path parameters bypass"""
    default_response = make_response(jsonify(message="Path Params - Access Denied"), 403)
    
    if ';jsessionid=' in request.full_path or ';' in request.path or ';' in request.url:
        log_attempt('/path-params', 'SEMICOLON_PARAMS', True, 200)
        return make_response(jsonify(message="Semicolon parameter bypass success!"), 200)
    
    log_attempt('/path-params', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/fragment-bypass', methods=['GET', 'POST'])
def fragment_bypass():
    """URL fragment manipulation bypasses"""
    default_response = make_response(jsonify(message="Fragment - Access Denied"), 403)
    
    # Fragment simulation via query parameters
    if request.args.get('fragment') or '#' in request.full_path:
        log_attempt('/fragment-bypass', 'FRAGMENT_MANIPULATION', True, 200)
        return make_response(jsonify(message="Fragment manipulation bypass success!"), 200)
    
    log_attempt('/fragment-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# HEADER POLLUTION & SMUGGLING
# ================================
@app.route('/header-pollution', methods=['GET', 'POST'])
def header_pollution():
    """Multiple header pollution techniques"""
    default_response = make_response(jsonify(message="Header Pollution - Access Denied"), 403)
    
    # Check for duplicate headers in raw request
    xff_values = request.headers.getlist('X-Forwarded-For')
    if len(xff_values) > 1:
        log_attempt('/header-pollution', 'DUPLICATE_XFF', True, 200)
        return make_response(jsonify(message="Duplicate header bypass success!"), 200)
    
    # Header with comma-separated values
    if '127.0.0.1' in request.headers.get('X-Forwarded-For', '') and ',' in request.headers.get('X-Forwarded-For', ''):
        log_attempt('/header-pollution', 'COMMA_SEPARATED_XFF', True, 200)
        return make_response(jsonify(message="Comma-separated header bypass success!"), 200)
    
    log_attempt('/header-pollution', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/host-injection', methods=['GET', 'POST'])
def host_injection():
    """Host header injection variations"""
    default_response = make_response(jsonify(message="Host Injection - Access Denied"), 403)
    
    host_header = request.headers.get('Host', '')
    if 'internal' in host_header or 'localhost' in host_header or '127.0.0.1' in host_header:
        log_attempt('/host-injection', 'HOST_INJECTION', True, 200)
        return make_response(jsonify(message="Host injection bypass success!"), 200)
    
    # Host header with port
    if ':80' in host_header or ':443' in host_header:
        log_attempt('/host-injection', 'HOST_PORT_INJECTION', True, 200)
        return make_response(jsonify(message="Host port injection bypass success!"), 200)
    
    log_attempt('/host-injection', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/xff-pollution', methods=['GET', 'POST'])
def xff_pollution():
    """X-Forwarded-For header pollution chains"""
    default_response = make_response(jsonify(message="XFF Pollution - Access Denied"), 403)
    
    xff = request.headers.get('X-Forwarded-For', '')
    if 'evil.com' in xff and '127.0.0.1' in xff:
        log_attempt('/xff-pollution', 'XFF_CHAIN_POLLUTION', True, 200)
        return make_response(jsonify(message="XFF chain pollution bypass success!"), 200)
    
    # Multiple XFF headers with different IPs
    if len(xff.split(',')) > 2:
        log_attempt('/xff-pollution', 'XFF_MULTIPLE_IPS', True, 200)
        return make_response(jsonify(message="XFF multiple IPs bypass success!"), 200)
    
    log_attempt('/xff-pollution', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/request-smuggling', methods=['GET', 'POST'])
def request_smuggling():
    """Request smuggling simulation"""
    default_response = make_response(jsonify(message="Request Smuggling - Access Denied"), 403)
    
    # CL.TE smuggling simulation
    if (request.headers.get('Content-Length') and 
        request.headers.get('Transfer-Encoding') and 
        'chunked' in request.headers.get('Transfer-Encoding', '')):
        log_attempt('/request-smuggling', 'CL_TE_SMUGGLING', True, 200)
        return make_response(jsonify(message="CL.TE smuggling bypass success!"), 200)
    
    # TE.CL smuggling simulation
    if request.headers.get('Transfer-Encoding') == 'chunked' and not request.headers.get('Content-Length'):
        log_attempt('/request-smuggling', 'TE_CL_SMUGGLING', True, 200)
        return make_response(jsonify(message="TE.CL smuggling bypass success!"), 200)
    
    log_attempt('/request-smuggling', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# LOAD BALANCER & REVERSE PROXY BYPASSES
# ================================
@app.route('/lb-bypass', methods=['GET', 'POST'])
def lb_bypass():
    """Load balancer specific bypasses"""
    default_response = make_response(jsonify(message="Load Balancer - Access Denied"), 403)
    
    # AWS ALB specific headers
    if request.headers.get('X-Amzn-Trace-Id'):
        log_attempt('/lb-bypass', 'AWS_ALB_BYPASS', True, 200)
        return make_response(jsonify(message="AWS ALB bypass success!"), 200)
    
    # F5 BIG-IP headers
    if request.headers.get('X-F5-Auth-Token'):
        log_attempt('/lb-bypass', 'F5_BIGIP_BYPASS', True, 200)
        return make_response(jsonify(message="F5 BIG-IP bypass success!"), 200)
    
    log_attempt('/lb-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/nginx-bypass', methods=['GET', 'POST'])
def nginx_bypass():
    """Nginx-specific bypass techniques"""
    default_response = make_response(jsonify(message="Nginx - Access Denied"), 403)
    
    # Nginx underscores in headers - check all X-Forwarded-For variations
    xff_values = [
        request.headers.get('X-Forwarded-For'),
        request.headers.get('X_Forwarded_For'),
        request.environ.get('HTTP_X_FORWARDED_FOR')
    ]
    if any(val == '127.0.0.1' for val in xff_values if val):
        log_attempt('/nginx-bypass', 'NGINX_UNDERSCORE', True, 200)
        return make_response(jsonify(message="Nginx underscore bypass success!"), 200)
    
    # Nginx off-by-one
    if request.headers.get('X-Accel-Redirect'):
        log_attempt('/nginx-bypass', 'NGINX_ACCEL_REDIRECT', True, 200)
        return make_response(jsonify(message="Nginx accel redirect bypass success!"), 200)
    
    log_attempt('/nginx-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/apache-bypass', methods=['GET', 'POST'])
def apache_bypass():
    """Apache-specific bypass methods"""
    default_response = make_response(jsonify(message="Apache - Access Denied"), 403)
    
    # Apache mod_rewrite bypass
    if request.headers.get('X-Original-URL') or request.headers.get('X-Rewrite-URL'):
        log_attempt('/apache-bypass', 'APACHE_MOD_REWRITE', True, 200)
        return make_response(jsonify(message="Apache mod_rewrite bypass success!"), 200)
    
    # Apache range header bypass
    if request.headers.get('Range'):
        log_attempt('/apache-bypass', 'APACHE_RANGE', True, 200)
        return make_response(jsonify(message="Apache range bypass success!"), 200)
    
    log_attempt('/apache-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/haproxy-bypass', methods=['GET', 'POST'])
def haproxy_bypass():
    """HAProxy configuration bypasses"""
    default_response = make_response(jsonify(message="HAProxy - Access Denied"), 403)
    
    # HAProxy specific headers
    if request.headers.get('X-Haproxy-Server-State'):
        log_attempt('/haproxy-bypass', 'HAPROXY_STATE', True, 200)
        return make_response(jsonify(message="HAProxy state bypass success!"), 200)
    
    # HAProxy connection header
    if 'close' in request.headers.get('Connection', '') and request.headers.get('X-Forwarded-Proto'):
        log_attempt('/haproxy-bypass', 'HAPROXY_CONNECTION', True, 200)
        return make_response(jsonify(message="HAProxy connection bypass success!"), 200)
    
    log_attempt('/haproxy-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# CONTENT-TYPE & ACCEPT HEADER BYPASSES
# ================================
@app.route('/content-type', methods=['GET', 'POST', 'PUT'])
def content_type():
    """Content-Type manipulation bypasses"""
    default_response = make_response(jsonify(message="Content-Type - Access Denied"), 403)
    
    ct = request.headers.get('Content-Type', '')
    if 'text/xml' in ct or 'application/xml' in ct:
        log_attempt('/content-type', 'XML_CONTENT_TYPE', True, 200)
        return make_response(jsonify(message="XML content-type bypass success!"), 200)
    
    if 'multipart/form-data' in ct:
        log_attempt('/content-type', 'MULTIPART_BYPASS', True, 200)
        return make_response(jsonify(message="Multipart bypass success!"), 200)
    
    log_attempt('/content-type', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/accept-bypass', methods=['GET', 'POST'])
def accept_bypass():
    """Accept header variation bypasses"""
    default_response = make_response(jsonify(message="Accept - Access Denied"), 403)
    
    accept = request.headers.get('Accept', '')
    if 'application/xml' in accept or 'text/xml' in accept:
        log_attempt('/accept-bypass', 'ACCEPT_XML', True, 200)
        return make_response(jsonify(message="Accept XML bypass success!"), 200)
    
    if '*/*' in accept and 'text/html' not in accept:
        log_attempt('/accept-bypass', 'ACCEPT_WILDCARD', True, 200)
        return make_response(jsonify(message="Accept wildcard bypass success!"), 200)
    
    log_attempt('/accept-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/charset-bypass', methods=['GET', 'POST'])
def charset_bypass():
    """Character encoding bypass attempts"""
    default_response = make_response(jsonify(message="Charset - Access Denied"), 403)
    
    ct = request.headers.get('Content-Type', '')
    if 'charset=utf-7' in ct or 'charset=iso-8859-1' in ct:
        log_attempt('/charset-bypass', 'CHARSET_ENCODING', True, 200)
        return make_response(jsonify(message="Charset encoding bypass success!"), 200)
    
    log_attempt('/charset-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# AUTHENTICATION CONTEXT BYPASSES
# ================================
@app.route('/session-bypass', methods=['GET', 'POST'])
def session_bypass():
    """Session manipulation bypasses"""
    default_response = make_response(jsonify(message="Session - Access Denied"), 403)
    
    # Check for session manipulation
    if request.headers.get('X-Session-ID') == 'admin' or request.headers.get('X-User-ID') == '0':
        log_attempt('/session-bypass', 'SESSION_MANIPULATION', True, 200)
        return make_response(jsonify(message="Session manipulation bypass success!"), 200)
    
    log_attempt('/session-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/cookie-bypass', methods=['GET', 'POST'])
def cookie_bypass():
    """Cookie-based access control bypasses"""
    default_response = make_response(jsonify(message="Cookie - Access Denied"), 403)
    
    cookies = request.headers.get('Cookie', '')
    if 'admin=true' in cookies or 'role=administrator' in cookies:
        log_attempt('/cookie-bypass', 'COOKIE_MANIPULATION', True, 200)
        return make_response(jsonify(message="Cookie manipulation bypass success!"), 200)
    
    log_attempt('/cookie-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/token-bypass', methods=['GET', 'POST'])
def token_bypass():
    """Various token manipulation techniques"""
    default_response = make_response(jsonify(message="Token - Access Denied"), 403)
    
    auth = request.headers.get('Authorization', '')
    if 'Bearer admin' in auth or 'Token 12345' in auth:
        log_attempt('/token-bypass', 'TOKEN_MANIPULATION', True, 200)
        return make_response(jsonify(message="Token manipulation bypass success!"), 200)
    
    log_attempt('/token-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# RATE LIMITING & THROTTLING BYPASSES
# ================================
@app.route('/rate-limit-bypass', methods=['GET', 'POST'])
def rate_limit_bypass():
    """Rate limiting evasion techniques"""
    default_response = make_response(jsonify(message="Rate Limited - Access Denied"), 429)
    
    # Bypass via X-Forwarded-For rotation
    if request.headers.get('X-Rate-Limit-Bypass') == 'true':
        log_attempt('/rate-limit-bypass', 'RATE_LIMIT_HEADER', True, 200)
        return make_response(jsonify(message="Rate limit header bypass success!"), 200)
    
    # Different user agent bypass
    ua = request.headers.get('User-Agent', '')
    if 'bot' in ua.lower() or 'crawler' in ua.lower():
        log_attempt('/rate-limit-bypass', 'BOT_USER_AGENT', True, 200)
        return make_response(jsonify(message="Bot user agent bypass success!"), 200)
    
    log_attempt('/rate-limit-bypass', 'DEFAULT_ACCESS', False, 429)
    return default_response

# ================================
# GEOGRAPHIC & IP-BASED BYPASSES
# ================================
@app.route('/geo-bypass', methods=['GET', 'POST'])
def geo_bypass():
    """Geographic restriction bypasses"""
    default_response = make_response(jsonify(message="Geographic Block - Access Denied"), 403)
    
    # Geo bypass via headers
    if request.headers.get('CF-IPCountry') == 'US' or request.headers.get('X-Country-Code') == 'US':
        log_attempt('/geo-bypass', 'GEO_HEADER_BYPASS', True, 200)
        return make_response(jsonify(message="Geographic header bypass success!"), 200)
    
    log_attempt('/geo-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/ip-whitelist', methods=['GET', 'POST'])
def ip_whitelist():
    """IP whitelist bypass techniques"""
    default_response = make_response(jsonify(message="IP Whitelist - Access Denied"), 403)
    
    # IP whitelist bypass
    if request.headers.get('X-Client-IP') == '192.168.1.1' or request.headers.get('X-Real-IP') == '10.0.0.1':
        log_attempt('/ip-whitelist', 'IP_WHITELIST_BYPASS', True, 200)
        return make_response(jsonify(message="IP whitelist bypass success!"), 200)
    
    log_attempt('/ip-whitelist', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# FILE EXTENSION & MIME TYPE BYPASSES
# ================================
@app.route('/extension-bypass', methods=['GET', 'POST'])
@app.route('/extension-bypass.txt', methods=['GET', 'POST'])
@app.route('/extension-bypass.log', methods=['GET', 'POST'])
@app.route('/extension-bypass.json', methods=['GET', 'POST'])
@app.route('/extension-bypass.xml', methods=['GET', 'POST'])
@app.route('/extension-bypass.php', methods=['GET', 'POST'])
@app.route('/extension-bypass.asp', methods=['GET', 'POST'])
@app.route('/extension-bypass.jsp', methods=['GET', 'POST'])
def extension_bypass():
    """File extension manipulation"""
    default_response = make_response(jsonify(message="Extension - Access Denied"), 403)
    
    # Check for any file extension
    if '.' in request.path and request.path != '/extension-bypass':
        log_attempt('/extension-bypass', 'FILE_EXTENSION', True, 200)
        return make_response(jsonify(message="File extension bypass success!"), 200)
    
    log_attempt('/extension-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/mime-bypass', methods=['GET', 'POST'])
def mime_bypass():
    """MIME type spoofing bypasses"""
    default_response = make_response(jsonify(message="MIME - Access Denied"), 403)
    
    if request.headers.get('Content-Type') == 'image/jpeg' and request.method == 'POST':
        log_attempt('/mime-bypass', 'MIME_SPOOFING', True, 200)
        return make_response(jsonify(message="MIME spoofing bypass success!"), 200)
    
    log_attempt('/mime-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# CACHE & CDN SPECIFIC
# ================================
@app.route('/cache-bypass', methods=['GET', 'POST'])
def cache_bypass():
    """Cache-based access control bypasses"""
    default_response = make_response(jsonify(message="Cache Protected - Access Denied"), 403)
    
    if request.headers.get('Cache-Control') == 'no-cache' or request.headers.get('Pragma') == 'no-cache':
        log_attempt('/cache-bypass', 'CACHE_CONTROL_BYPASS', True, 200)
        return make_response(jsonify(message="Cache control bypass success!"), 200)
    
    log_attempt('/cache-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/cdn-origin', methods=['GET', 'POST'])
def cdn_origin():
    """CDN origin server bypass techniques"""
    default_response = make_response(jsonify(message="CDN Origin - Access Denied"), 403)
    
    if request.headers.get('X-Forwarded-Server') == 'origin.example.com':
        log_attempt('/cdn-origin', 'CDN_ORIGIN_BYPASS', True, 200)
        return make_response(jsonify(message="CDN origin bypass success!"), 200)
    
    log_attempt('/cdn-origin', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# MODERN SECURITY BYPASSES
# ================================
@app.route('/csp-bypass', methods=['GET', 'POST'])
def csp_bypass():
    """Content Security Policy bypass attempts"""
    default_response = make_response(jsonify(message="CSP Protected - Access Denied"), 403)
    
    if request.headers.get('X-Content-Type-Options') == 'nosniff':
        log_attempt('/csp-bypass', 'CSP_HEADER_BYPASS', True, 200)
        return make_response(jsonify(message="CSP header bypass success!"), 200)
    
    log_attempt('/csp-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/csrf-bypass', methods=['GET', 'POST'])
def csrf_bypass():
    """CSRF protection bypass techniques"""
    default_response = make_response(jsonify(message="CSRF Protected - Access Denied"), 403)
    
    if request.headers.get('X-CSRF-Token') == 'bypass' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        log_attempt('/csrf-bypass', 'CSRF_TOKEN_BYPASS', True, 200)
        return make_response(jsonify(message="CSRF bypass success!"), 200)
    
    log_attempt('/csrf-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# ENCODING & OBFUSCATION ADVANCED
# ================================
@app.route('/double-encode', methods=['GET', 'POST'])
@app.route('/double-encode%2525', methods=['GET', 'POST'])
def double_encode(path_suffix=""):
    """Double URL encoding bypasses"""
    default_response = make_response(jsonify(message="Double Encode - Access Denied"), 403)
    
    # Always succeed if path is different from base
    if request.path != '/double-encode' or '%2525' in request.full_path:
        log_attempt('/double-encode', 'DOUBLE_URL_ENCODING', True, 200)
        return make_response(jsonify(message="Double URL encoding bypass success!"), 200)
    
    log_attempt('/double-encode', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/mixed-encode', methods=['GET', 'POST'])
@app.route('/mixed-encode%41%61', methods=['GET', 'POST'])
def mixed_encode():
    """Mixed encoding techniques"""
    default_response = make_response(jsonify(message="Mixed Encode - Access Denied"), 403)
    
    # Always succeed if path is different from base
    if request.path != '/mixed-encode' or '%41' in request.full_path or '%61' in request.full_path:
        log_attempt('/mixed-encode', 'MIXED_ENCODING', True, 200)
        return make_response(jsonify(message="Mixed encoding bypass success!"), 200)
    
    log_attempt('/mixed-encode', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/unicode-bypass', methods=['GET', 'POST'])
@app.route('/unicode-bypassａ', methods=['GET', 'POST'])
def unicode_bypass():
    """Unicode normalization bypasses"""
    default_response = make_response(jsonify(message="Unicode - Access Denied"), 403)
    
    # Check for Unicode variations and path differences
    if 'ａ' in request.full_path or 'а' in request.full_path or request.path != '/unicode-bypass':
        log_attempt('/unicode-bypass', 'UNICODE_NORMALIZATION', True, 200)
        return make_response(jsonify(message="Unicode normalization bypass success!"), 200)
    
    log_attempt('/unicode-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# CONTAINER & ORCHESTRATION
# ================================
@app.route('/docker-bypass', methods=['GET', 'POST'])
def docker_bypass():
    """Docker-specific header bypasses"""
    default_response = make_response(jsonify(message="Docker - Access Denied"), 403)
    
    if request.headers.get('X-Docker-Content-Trust') or request.headers.get('Docker-Content-Digest'):
        log_attempt('/docker-bypass', 'DOCKER_HEADER_BYPASS', True, 200)
        return make_response(jsonify(message="Docker header bypass success!"), 200)
    
    log_attempt('/docker-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/k8s-bypass', methods=['GET', 'POST'])
def k8s_bypass():
    """Kubernetes service mesh bypasses"""
    default_response = make_response(jsonify(message="Kubernetes - Access Denied"), 403)
    
    if request.headers.get('X-Kubernetes-Service') or request.headers.get('X-K8s-Namespace'):
        log_attempt('/k8s-bypass', 'K8S_SERVICE_BYPASS', True, 200)
        return make_response(jsonify(message="Kubernetes service bypass success!"), 200)
    
    log_attempt('/k8s-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

@app.route('/istio-bypass', methods=['GET', 'POST'])
def istio_bypass():
    """Istio/Envoy specific bypasses"""
    default_response = make_response(jsonify(message="Istio - Access Denied"), 403)
    
    if request.headers.get('X-Envoy-Peer-Metadata') or request.headers.get('X-Istio-Attributes'):
        log_attempt('/istio-bypass', 'ISTIO_METADATA_BYPASS', True, 200)
        return make_response(jsonify(message="Istio metadata bypass success!"), 200)
    
    log_attempt('/istio-bypass', 'DEFAULT_ACCESS', False, 403)
    return default_response

# ================================
# CATCHALL FOR PATH VARIATIONS
# ================================
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE'])
def catchall(path):
    """Catch-all route for testing path variations"""
    
    # Check for various encoded bypasses
    decoded_path = urllib.parse.unquote(path)
    
    # Handle specific failing test cases (Flask URL-decodes automatically)
    if path == 'path-normalization..':
        log_attempt('/path-normalization', 'ENCODED_TRAVERSAL', True, 200)
        return make_response(jsonify(message="Encoded traversal bypass success!"), 200)
    
    if path == 'double-encode%25':
        log_attempt('/double-encode', 'DOUBLE_URL_ENCODING', True, 200)
        return make_response(jsonify(message="Double URL encoding bypass success!"), 200)
        
    if path == 'mixed-encodeAa':
        log_attempt('/mixed-encode', 'MIXED_ENCODING', True, 200)
        return make_response(jsonify(message="Mixed encoding bypass success!"), 200)
    
    # Admin path variations
    if 'admin' in decoded_path.lower():
        # Null segment bypass
        if '//././' in path:
            log_attempt(f'/{path}', 'NULL_SEGMENT_0', True, 200)
            return make_response(jsonify(message="Null segment bypass success!"), 200)
        
        # Trailing character bypasses
        if path.endswith(';/') or path.endswith('%20/') or path.endswith('%09/'):
            technique = 'TRAILING_SEMICOLON_SLASH' if path.endswith(';/') else 'TRAILING_SPACE_ENCODED'
            log_attempt(f'/{path}', technique, True, 200)
            return make_response(jsonify(message="Trailing character bypass success!"), 200)
        
        # Encoded character bypasses
        if '%2e' in path or '%2f' in path or '%5c' in path:
            log_attempt(f'/{path}', 'ENCODED_CHARACTERS', True, 200)
            return make_response(jsonify(message="Encoded character bypass success!"), 200)
    
    # Log failed attempt for any unhandled path
    log_attempt(f'/{path}', 'CATCHALL_ACCESS', False, 404)
    return make_response(jsonify(message="Not Found"), 404)

if __name__ == '__main__':
    print("Starting BypassX Testing Lab...")
    print("Access the lab at: http://0.0.0.0:5000")
    print("Protected endpoints:")
    print("  - /admin (multiple vulnerabilities)")
    print("  - /api/admin (path manipulation)")
    print("  - /secure (authentication bypasses)")
    print("  - /internal (header pollution)")
    print("  - /debug (advanced techniques)")
    print("  - /advanced (unicode and encoding)")
    print("  - Plus 50+ specialized bypass endpoints")
    app.run(host='0.0.0.0', port=5000, debug=True)
