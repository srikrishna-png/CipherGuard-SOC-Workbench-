import urllib.request, json

def test_api(name, input_str):
    req = urllib.request.Request(
        'http://127.0.0.1:8000/api/v1/tools/access_log_parser/analyze',
        data=json.dumps({'input_text': input_str, 'params': {}}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        print(f"{name} -> Verdict: {data['verdict']} | Risk Score: {data['risk_score']} | Summary: {data['summary']}")

test_api('TC1 Clean', '192.168.1.50 - - [19/Sep/2026:10:15:32 +0530] "GET /index.html HTTP/1.1" 200 1234')
test_api('TC2 SQLi', "45.142.213.88 - - [19/Sep/2026:10:15:32 +0530] \"GET /admin.php?id=1' OR '1'='1 HTTP/1.1\" 500 0")
test_api('TC3 XSS', '103.75.201.2 - - [19/Sep/2026:10:15:32 +0530] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 5678')
