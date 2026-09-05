import urllib.request
import ssl
import re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
}

req = urllib.request.Request('https://macnibe.interieur.gov.dz/WFReadCardFr.aspx', headers=headers)
try:
    with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
        html = r.read().decode('utf-8', errors='ignore')
        print(f"Page WFReadCardFr.aspx reçue : {len(html)} octets")
        
        # Trouver WebMethods ASP.NET
        methods = set(re.findall(r'WFReadCard[a-zA-Z0-9_\/]*\.aspx\/[a-zA-Z0-9_]+', html))
        print("WebMethods détectées dans la page :", methods)

        # Chercher dans les scripts JS
        js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html, re.IGNORECASE)
        print("Fichiers JS inclus :", js_files)
        
        for js in js_files:
            if not js.startswith('http'):
                js_url = f"https://macnibe.interieur.gov.dz/{js.lstrip('/')}"
            else:
                js_url = js
            try:
                js_req = urllib.request.Request(js_url, headers=headers)
                with urllib.request.urlopen(js_req, context=ctx, timeout=10) as jr:
                    js_content = jr.read().decode('utf-8', errors='ignore')
                    js_methods = set(re.findall(r'[\w\./]+\.aspx\/[a-zA-Z0-9_]+', js_content))
                    if js_methods:
                        print(f"WebMethods dans {js} :", js_methods)
            except Exception as ex:
                pass

except Exception as e:
    print("Erreur:", e)
