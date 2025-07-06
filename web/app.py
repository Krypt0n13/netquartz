import os
import sys
import json
import subprocess
from datetime import datetime
from vlans_helper import snmp_get_vlans, save_vlans, load_vlans


from flask import (
    Flask, request, render_template,
    redirect, url_for, flash
)
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import check_password_hash, generate_password_hash

from models import User

app = Flask(__name__)
app.secret_key = 'your-secret-key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

SAVED_DEVICES_FOLDER = os.path.join(app.root_path, 'saved_devices')
USERS_FILE = os.path.join(app.root_path, 'users.json')

@login_manager.user_loader
def load_user(user_id):
    return User.load_by_id(user_id)


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    result = None
    if request.method == 'POST':
        ip = request.form['ip']
        community = request.form['community']
        venv_python = sys.executable

        proc = subprocess.Popen(
            [venv_python, '../collectors/cisco_snmp.py', ip, community],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate()

        if proc.returncode != 0:
            result = {
                "error": "Script error",
                "details": stderr.decode('utf-8')
            }
        else:
            try:
                result = json.loads(stdout.decode('utf-8'))
            except json.JSONDecodeError:
                result = {
                    "error": "Invalid JSON output",
                    "raw_output": stdout.decode('utf-8'),
                    "stderr": stderr.decode('utf-8')
                }
    return render_template('index.html', result=result)


@app.route('/save-device', methods=['POST'])
@login_required
def save_device():
    if getattr(current_user, 'is_readonly', False):
        flash("Du hast keine Berechtigung zum Speichern von Geräten.", "danger")
        return redirect(url_for('index'))
    data = request.form.get('device_data', '').strip()
    if not data:
        flash("No device data provided.", "danger")
        return redirect(url_for('index'))
    try:
        device_json = json.loads(data)
    except json.JSONDecodeError:
        flash("Invalid JSON format.", "danger")
        return redirect(url_for('index'))

    os.makedirs(SAVED_DEVICES_FOLDER, exist_ok=True)

    hostname = device_json.get("device", {}).get("hostname")
    if hostname:
        filename = f"device_{hostname}.json"
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"device_{timestamp}.json"

    filepath = os.path.join(SAVED_DEVICES_FOLDER, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(data)

    flash('Device saved successfully.', 'success')
    return redirect(url_for('index'))


@app.route('/device/<filename>')
@login_required
def device_detail(filename):
    path = os.path.join(SAVED_DEVICES_FOLDER, filename)
    if not os.path.isfile(path):
        return "Device not found", 404
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return render_template('index.html', result=data)

@app.route('/users/edit/<user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash("Zugriff verweigert", "warning")
        return redirect(url_for('index'))
    
    users = load_users_file()
    user = next((u for u in users if u['id'] == user_id), None)
    if not user:
        flash("Benutzer nicht gefunden.", "danger")
        return redirect(url_for('list_users'))

    if request.method == 'POST':
        # Felder aktualisieren
        user['fullname'] = request.form.get('fullname', user.get('fullname', '')).strip()
        user['username'] = request.form.get('username', user.get('username', '')).strip()
        user['email'] = request.form.get('email', user.get('email', '')).strip()
        user['role'] = request.form.get('role', user.get('role', 'user'))

        # Nur Passwort setzen, wenn eingegeben
        new_password = request.form.get('password', '').strip()
        if new_password:
            user['password'] = generate_password_hash(new_password)

        # JSON speichern
        save_users_file(users)

        flash("Benutzer aktualisiert.", "success")
        return redirect(url_for('list_users'))

    return render_template('edit_user.html', user=user)


@app.route('/vlans', methods=['GET', 'POST'])
@login_required
def vlans():
    vlans = []
    hostname = ''
    error = None

    if request.method == 'POST':
        ip = request.form['ip']
        community = request.form['community']
        try:
            vlans, hostname = snmp_get_vlans(ip, community)
            save_vlans(vlans, hostname)
        except Exception as e:
            error = f"Fehler beim Abrufen: {e}"

    saved_vlans = load_vlans()
    page = int(request.args.get("page", 1))
    per_page = 10
    total_pages = max(1, (len(saved_vlans) + per_page - 1) // per_page)
    paged_vlans = saved_vlans[(page-1)*per_page : page*per_page]

    return render_template('vlans.html',
                           vlans=vlans,
                           hostname=hostname,
                           saved_vlans=paged_vlans,
                           error=error,
                           total_pages=total_pages,
                           current_page=page)



@app.route('/vlans/delete', methods=['POST'])
@login_required
def delete_vlan():
    vlan_id = request.form.get('vlan_id')
    hostname = request.form.get('hostname')

    data = load_vlans()
    updated = []

    for entry in data:
        if entry['id'] == vlan_id and hostname in entry.get("hostname", ""):
            host_list = entry["hostname"].split(", ")
            host_list = [h for h in host_list if h != hostname]
            if host_list:
                entry["hostname"] = ", ".join(host_list)
                updated.append(entry)
            # wenn kein Host übrig ist, VLAN nicht mehr speichern
        else:
            updated.append(entry)

    with open('vlans.json', 'w', encoding='utf-8') as f:
        json.dump(updated, f, indent=2, ensure_ascii=False)

    flash(f"VLAN {vlan_id} von {hostname} gelöscht.", "success")
    return redirect(url_for('vlans'))



@app.route('/delete-device/<filename>', methods=['POST'])
@login_required
def delete_device(filename):
    if getattr(current_user, 'is_readonly', False):
        flash("Du hast keine Berechtigungen zum Löschen von Geräten.", "danger")
        return redirect(url_for('index'))
    path = os.path.join(SAVED_DEVICES_FOLDER, filename)
    if os.path.isfile(path):
        os.remove(path)
        flash('Device deleted successfully.', 'success')
    else:
        flash('Device not found.', 'danger')
    return redirect(url_for('devices'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.get_by_username(username)
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ------------------------------------------------
# User-Management
# ------------------------------------------------

def load_users_file():
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_users_file(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

@app.route('/users')
@login_required
def list_users():
    if not current_user.is_admin:
        flash("Zugriff verweigert", "warning")
        return redirect(url_for('index'))
    users = load_users_file()
    return render_template('users.html', users=users)

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        flash("Zugriff verweigert", "warning")
        return redirect(url_for('index'))

    if request.method == 'POST':
        fullname = request.form['fullname'].strip()
        username = request.form['username'].strip()
        password = request.form['password']
        email = request.form['email'].strip()
        role = request.form.get('role', 'user')

        if not fullname or not username or not password or not email:
            flash("Alle Felder ausfüllen!", "danger")
            return redirect(url_for('create_user'))

        users = load_users_file()
        new_id = str(max([int(u['id']) for u in users] + [0]) + 1)
        hashed = generate_password_hash(password, method='scrypt')

        users.append({
            "id": new_id,
            "username": username,
            "fullname": fullname,
            "email": email,
            "password": hashed,
            "role": role
        })

        save_users_file(users)
        flash(f"User {username} angelegt.", "success")
        return redirect(url_for('list_users'))

    return render_template('create_user.html')


@app.route('/users/delete', methods=['POST'])
@login_required
def delete_user():
    if not current_user.is_admin:
        flash("Zugriff verweigert", "warning")
        return redirect(url_for('index'))

    user_id = request.form.get('user_id')  # aus dem Formular
    users = load_users_file()

    # 👇 Debug-Ausgabe einfügen
    print(f"⚙️ [DEBUG] user_id from form: {user_id}")
    print(f"⚙️ [DEBUG] IDs in users list: {[str(u['id']) for u in users]}")

    if user_id == current_user.id:
        flash("Du kannst dich nicht selbst löschen!", "danger")
        return redirect(url_for('list_users'))

    new_list = [u for u in users if str(u['id']) != str(user_id)]

    if len(new_list) == len(users):
        flash("User nicht gefunden.", "warning")
    else:
        save_users_file(new_list)
        flash("User gelöscht.", "success")

    return redirect(url_for('list_users'))
import json, os

VLANS_FILE = "vlans.json"

def load_all_vlans():
    if os.path.exists(VLANS_FILE):
        with open(VLANS_FILE) as f:
            return json.load(f)
    return []



@app.route("/vlans", methods=["GET", "POST"])
@login_required
def vlan_import():
    vlans = []
    hostname = ""
    error = None

    if request.method == "POST":
        ip = request.form["ip"]
        community = request.form["community"]

        try:
            vlans = get_vlans_from_switch(ip, community)
            hostname = ip
            save_vlans(vlans)
        except Exception as e:
            error = f"Fehler beim Abrufen der VLANs: {e}"

    saved_vlans = load_all_vlans()
    return render_template("vlans.html", vlans=vlans, hostname=hostname, saved_vlans=saved_vlans, error=error)

from pysnmp.hlapi import *

def get_vlans_from_switch(ip, community):
    vlan_data = []

    # OIDs für VLAN ID und VLAN Name
    vlan_id_oid = ObjectIdentity('1.3.6.1.4.1.9.9.46.1.3.1.1.1')  # vmVlan
    vlan_name_oid = ObjectIdentity('1.3.6.1.4.1.9.9.46.1.3.1.1.4')  # vmVlanName

    # VLAN-Namen abfragen
    name_dict = {}
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=0),
        UdpTransportTarget((ip, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(vlan_name_oid),
        lexicographicMode=False
    ):
        if errorIndication:
            raise Exception(errorIndication)
        elif errorStatus:
            raise Exception(f'{errorStatus.prettyPrint()} at {errorIndex}')
        else:
            for varBind in varBinds:
                oid, value = varBind
                vlan_index = oid.prettyPrint().split('.')[-1]
                name_dict[vlan_index] = str(value)

    # VLAN-IDs abfragen (und mit Namen mergen)
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=0),
        UdpTransportTarget((ip, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(vlan_id_oid),
        lexicographicMode=False
    ):
        if errorIndication:
            raise Exception(errorIndication)
        elif errorStatus:
            raise Exception(f'{errorStatus.prettyPrint()} at {errorIndex}')
        else:
            for varBind in varBinds:
                oid, value = varBind
                vlan_index = oid.prettyPrint().split('.')[-1]
                vlan_id = int(value)
                vlan_name = name_dict.get(vlan_index, f"VLAN-{vlan_id}")
                vlan_data.append({
                    "id": vlan_id,
                    "name": vlan_name,
                    "hostname": ip
                })

    return vlan_data

SAVED_VLANS_FOLDER = os.path.join(app.root_path, 'saved_vlans')
os.makedirs(SAVED_VLANS_FOLDER, exist_ok=True)

from math import ceil
from flask import request

@app.route('/vlans', methods=['GET', 'POST'])
@login_required
def vlan_list():
    vlans = []
    hostname = ''
    error = None

    if request.method == 'POST':
        ip = request.form.get('ip')
        community = request.form.get('community')
        try:
            vlans = snmp_get_vlans(ip, community)
            hostname = ip
            save_vlans({'hostname': hostname, 'vlans': vlans})
        except Exception as e:
            error = f"Fehler beim Abrufen: {e}"

    # Alle gespeicherten VLANs laden
    all_data = load_vlans()

    # Flache Liste erstellen
    flat_vlans = []
    for device in all_data:
        for vlan in device.get("vlans", []):
            flat_vlans.append({
                "id": vlan.get("id"),
                "name": vlan.get("name"),
                "hostname": device.get("hostname")
            })

    # Pagination
    page = int(request.args.get("page", 1))
    per_page = 10
    total_pages = ceil(len(flat_vlans) / per_page)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_vlans = flat_vlans[start:end]

    return render_template('vlans.html',
                           vlans=vlans,
                           hostname=hostname,
                           saved_vlans=paginated_vlans,
                           error=error,
                           page=page,
                           total_pages=total_pages)



@app.route('/devices')
@login_required
def devices():
    query = request.args.get('query', '').strip().lower()
    devices = []

    if os.path.isdir(SAVED_DEVICES_FOLDER):
        for fname in sorted(os.listdir(SAVED_DEVICES_FOLDER)):
            if not fname.endswith('.json'):
                continue
            path = os.path.join(SAVED_DEVICES_FOLDER, fname)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                hostname = data.get("device", {}).get("hostname", "")
                model = data.get("device", {}).get("model", "")
                location = data.get("device", {}).get("location", "")

                if query and not (
                    query in hostname.lower() or
                    query in model.lower() or
                    query in location.lower()
                ):
                    continue

                devices.append({
                    "filename": fname,
                    "hostname": hostname or "Unknown",
                    "model": model or "Unknown",
                    "location": location or "Unknown",
                    "uptime": data.get("device", {}).get("uptime", "Unknown"),

                })
            except Exception as e:
                app.logger.warning(f"Could not load {fname}: {e}")



        return render_template('devices.html', devices=devices)

from datetime import datetime
import glob

@app.route('/dashboard')
@login_required
def dashboard():
    # Current time
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Devices info
    device_files = glob.glob(os.path.join(SAVED_DEVICES_FOLDER, '*.json'))
    num_devices = len(device_files)

    # Users info
    users = load_users_file()
    num_users = len(users)

    # Last updated device info
    last_updated = None
    last_hostname = None
    if device_files:
        latest_file = max(device_files, key=os.path.getmtime)
        last_updated = datetime.fromtimestamp(os.path.getmtime(latest_file)).strftime('%Y-%m-%d %H:%M:%S')
        try:
            with open(latest_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                last_hostname = data.get('device', {}).get('hostname', None)
        except Exception:
            last_hostname = None

    # Changelog - static example list for now
    changelog = [
        "Added new device discovery feature",
        "Improved user authentication",
        "Fixed bugs in device saving"
    ]

    return render_template('dashboard.html',
                           current_time=current_time,
                           num_devices=num_devices,
                           num_users=num_users,
                           last_updated=last_updated,
                           last_hostname=last_hostname,
                           changelog=changelog)


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current_password')
        new = request.form.get('new_password')
        confirm = request.form.get('confirm_password')

        if not check_password_hash(current_user.password, current):
            flash("Aktuelles Passwort ist falsch", "danger")
            return redirect(url_for('change_password'))
        
        if not new or new != confirm:
            flash("Die neuen Passwörter stimmen nicht überein.", "danger")
            return redirect(url_for('change_password'))
        
        # Update passwort
        users = load_users_file()
        for user in users:
            if user['id'] == current_user.id:
                user['password'] = generate_password_hash(new)
                break

        save_users_file(users)
        flash("Passwort erfolgreich geändert", "success")
        return redirect(url_for('index'))
    
    return render_template('change_password.html')

if __name__ == '__main__':
    app.run(debug=True)
