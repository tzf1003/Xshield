"""Intentionally vulnerable two-user origin, reachable only through local lab ports.

The business API accepts a lab identity header but never checks object ownership.
Keep this service out of production deployments.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from urllib.parse import urlsplit


ORDERS = {
    "order-a": {"id": "order-a", "owner": "alice", "amount": 31},
    "order-b": {"id": "order-b", "owner": "bob", "amount": 47},
}
PATIENTS = {
    "patient-c": {"id": "patient-c", "owner": "user_a", "name": "患者 C", "diagnosis": "观察中"},
    "patient-d": {"id": "patient-d", "owner": "user_a", "name": "患者 D", "diagnosis": "复诊"},
    "patient-e": {"id": "patient-e", "owner": "user_b", "name": "患者 E", "diagnosis": "治疗中"},
    "patient-f": {"id": "patient-f", "owner": "user_b", "name": "患者 F", "diagnosis": "已出院"},
}
USERS = {
    "user_a": "user-a-password",
    "user_b": "user-b-password",
    "alice": "alice-password",
    "bob": "bob-password",
}
REQUEST_COUNTS = {}
COUNT_LOCK = Lock()


def count(method, path):
    with COUNT_LOCK:
        key = f"{method} {path}"
        REQUEST_COUNTS[key] = REQUEST_COUNTS.get(key, 0) + 1


class Handler(BaseHTTPRequestHandler):
    def identity(self):
        bearer = self.headers.get("Authorization", "")
        if bearer.startswith("Bearer lab-token-"):
            return bearer.removeprefix("Bearer lab-token-")
        return ""

    def ownership_enforced(self):
        return self.headers.get("X-Xshield-Object-Access") == "enforce"

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(min(length, 16_384)))

    def do_POST(self):
        path = urlsplit(self.path).path
        count("POST", path)
        if path == "/login":
            body = self.read_json()
            user = body.get("username", "")
            password = body.get("password", "")
            if user not in USERS or USERS[user] != password:
                user = self.headers.get("X-Lab-User", "")
            if user not in USERS:
                return self.reply(401, {"error": "invalid_credentials"})
            return self.reply(200, {
                "identity": {"id": f"principal_{user}", "authorization_context": f"lab:{user}"},
                "access_token": f"lab-token-{user}",
            })
        if path.startswith("/patients/"):
            user = self.identity()
            if user not in ("user_a", "user_b"):
                return self.reply(401, {"error": "lab_identity_required"})
            patient = PATIENTS.get(path.removeprefix("/patients/"))
            if not patient:
                return self.reply(404, {"error": "not_found"})
            if self.ownership_enforced() and patient["owner"] != user:
                return self.reply(403, {"error": "object_access_denied", "reason_code": "OBJECT_OWNER_MISMATCH"})
            # Deliberately vulnerable: object ownership is not checked.
            update = self.read_json()
            patient.update({key: str(value) for key, value in update.items() if key in ("diagnosis", "notes")})
            return self.reply(200, patient)
        if path != "/login":
            return self.reply(404, {"error": "not_found"})

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/__lab/metrics":
            with COUNT_LOCK:
                return self.reply(200, dict(REQUEST_COUNTS))
        count("GET", path)
        if path == "/health":
            return self.reply(200, {"ok": True})
        if path == "/":
            return self.reply_html()
        user = self.identity()
        if user not in ("alice", "bob"):
            if user not in ("user_a", "user_b"):
                return self.reply(401, {"error": "lab_identity_required"})
            if path == "/patients":
                return self.reply(200, {"patients": [
                    {**patient, "_xshield_action_ref": "patients.open"}
                    for patient in PATIENTS.values() if patient["owner"] == user
                ]})
            if path.startswith("/patients/"):
                patient = PATIENTS.get(path.removeprefix("/patients/"))
                if self.ownership_enforced() and patient and patient["owner"] != user:
                    return self.reply(403, {"error": "object_access_denied", "reason_code": "OBJECT_OWNER_MISMATCH"})
                # Deliberately vulnerable: detail lookup trusts only the ID.
                return self.reply(200, patient) if patient else self.reply(404, {"error": "not_found"})
            return self.reply(404, {"error": "not_found"})
        if path == "/orders":
            return self.reply(200, {"orders": [order for order in ORDERS.values() if order["owner"] == user]})
        if path.startswith("/orders/"):
            order = ORDERS.get(path.removeprefix("/orders/"))
            return self.reply(200, order) if order else self.reply(404, {"error": "not_found"})
        return self.reply(404, {"error": "not_found"})

    def reply(self, status, payload):
        data = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def reply_html(self):
        html = """<!doctype html><html lang='zh-CN'><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>患者访问实验</title><style>
body{font:16px system-ui,sans-serif;max-width:840px;margin:32px auto;padding:0 20px;color:#173b3b;background:#f5faf9}
h1{margin-bottom:4px}section{background:white;padding:20px;margin:18px 0;border:1px solid #cbdcda;border-radius:10px}
label{display:block;margin:10px 0}input{padding:9px;width:min(350px,90%);font:inherit}
button{padding:9px 14px;margin:6px 7px 6px 0;background:#176c62;color:white;border:0;border-radius:5px;cursor:pointer}
button:disabled{opacity:.5}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#eaf2f1;padding:14px;min-height:50px}
.hint{color:#526b69}.patients button{display:block}
</style><h1>患者访问实验</h1>
<p class='hint'>登录后查看本人患者。可在“目标患者 ID”输入其他患者 ID，比较直连与 WAF 入口的响应。</p>
<section><h2>登录</h2><form id='login-form'>
<label>账号 <input id='username' autocomplete='username' required></label>
<label>密码 <input id='password' type='password' autocomplete='current-password' required></label>
<button>登录</button></form><div id='session'></div></section>
<section><h2>我的患者</h2><button id='load' disabled>加载我的患者</button><div id='patients' class='patients'></div></section>
<section><h2>详情与编辑</h2>
<label>目标患者 ID <input id='patient-id' placeholder='patient-c / patient-e'></label>
<button id='view' disabled>查看详情</button>
<label>诊断 <input id='diagnosis' placeholder='输入新的诊断'></label>
<button id='save' disabled>保存修改</button></section>
<section><h2>本次响应</h2><pre id='output'>请先登录</pre></section>
<script>
let token='';
const $=id=>document.getElementById(id);
async function call(path,method='GET',body){
  const headers={};if(token)headers.Authorization='Bearer '+token;
  if(body)headers['Content-Type']='application/json';
  try{const response=await fetch(path,{method,headers,body:body?JSON.stringify(body):undefined});
    const data=await response.json();
    $('output').textContent=JSON.stringify({status:response.status,request_id:response.headers.get('X-Xshield-Request-Id'),data},null,2);
    return {response,data};
  }catch(error){$('output').textContent=String(error);return null;}
}
$('login-form').onsubmit=async event=>{event.preventDefault();token='';
  const result=await call('/login','POST',{username:$('username').value,password:$('password').value});
  if(!result)return;token=result.data.access_token||'';
  $('session').textContent=token?'已登录：'+$('username').value:'登录失败';
  for(const id of ['load','view','save'])$(id).disabled=!token;
};
$('load').onclick=async()=>{const result=await call('/patients');if(!result)return;
  const box=$('patients');box.replaceChildren();
  for(const patient of result.data.patients||[]){const button=document.createElement('button');
    button.textContent=patient.name+' ('+patient.id+')';
    button.onclick=()=>{$('patient-id').value=patient.id;$('view').click()};box.append(button);}
};
$('view').onclick=()=>call('/patients/'+encodeURIComponent($('patient-id').value));
$('save').onclick=()=>call('/patients/'+encodeURIComponent($('patient-id').value),'POST',{diagnosis:$('diagnosis').value});
</script></html>"""
        data = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
