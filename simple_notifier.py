#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ========================================
# CORRECTIONS APPLIQUÉES :
# 1. ✅ Scrollbar réactivée pour la liste des alertes
# 2. ✅ Largeur des cadres responsive (s'adapte à la fenêtre)
# 3. ✅ Centrage amélioré des widgets
# ========================================

import atexit
import random
import socket
import tempfile

from winotify import Notification, audio
from pathlib import Path
import logging
import threading
import time
import paho.mqtt.client as mqtt
import json
import sys
import requests
import os
import tkinter as tk
from tkinter import Image, PhotoImage, ttk, messagebox, scrolledtext
from datetime import datetime
import queue
import winreg
import os
import sys
from pathlib import Path
import os, requests, logging
# Configuration de base
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from PIL import Image, ImageTk

import sys
if sys.platform == "win32":
    import ctypes
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
# Détermine si le script est exécuté en .exe ou en mode développement
is_exe = getattr(sys, 'frozen', False)

# Chemin du dossier courant (où se trouve le .exe ou le script)
current_dir = Path(sys.executable).parent if is_exe else Path(__file__).parent

# Chemin vers le fichier .env (à côté du .exe)
env_path = current_dir / ".env"

# Charge les variables d'environnement
load_dotenv(env_path)

# Configuration avec valeurs par défaut
CONFIG = {
    "app_id": os.getenv("APP_ID", "Zone X"),
    "app_name": os.getenv("APP_NAME", "Zone X"),
    "icon_path": os.getenv("ICON_PATH", str(Path.home() / "notifier_icon.png")),
    "mqtt_broker": os.getenv("MQTT_BROKER"),
    "HOST_server":os.getenv("HOST_server"),
    "mqtt_port": int(os.getenv("MQTT_PORT", 1883)),
    "django_port": int(os.getenv("DJANGO_PORT", 8001)),
    "config_file": str(Path.home() / '.mqtt_notifier_config.json')

}

# Test (à supprimer en production)
print("Fichier .env chargé depuis :", env_path)
print("Configuration :", CONFIG)

# File d'attente pour les notifications
notification_queue = queue.Queue()
notification_lock = threading.Lock()

# Stockage des alertes reçues pour l'interface
received_alerts = []
alerts_lock = threading.Lock()

# === CONFIGURATION DU LOGGING DÉTAILLÉ ===
def setup_detailed_logging():
    """Configure un logging détaillé pour toutes les actions"""
    log_file = Path.home() / 'zonex_descktop.log'
    
    # Créer un formateur détaillé
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s() - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Handler pour fichier
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Handler pour console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    
    # Configurer le logger racine
    logging.basicConfig(
        level=logging.DEBUG,
        handlers=[file_handler, console_handler]
    )
    
    print(f"📝 Logging détaillé configuré. Fichier: {log_file}")

# Appeler la configuration du logging
setup_detailed_logging()
import sys
import warnings

# Supprimer les warnings pkg_resources et WNDPROC
warnings.filterwarnings("ignore", category=UserWarning, module="win10toast_click")
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Filtrer les erreurs WNDPROC dans stderr
class StderrFilter:
    def __init__(self, stream):
        self.stream = stream
    
    def write(self, text):
        # Ignorer les erreurs WNDPROC
        if "WNDPROC" not in text and "WPARAM" not in text and "LRESULT" not in text:
            self.stream.write(text)
    
    def flush(self):
        self.stream.flush()

# Appliquer le filtre
sys.stderr = StderrFilter(sys.stderr)
class LoginWindow:
    """Fenêtre de login moderne avec email et mot de passe"""
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Connexion - ZoneX")
        self.root.geometry("500x500")
        self.root.configure(bg=COLORS["bg"])
        self.root.resizable(False, False)
        
        # Centrer la fenêtre
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.root.winfo_screenheight() // 2) - (450 // 2)
        self.root.geometry(f"500x500+{x}+{y}")
        
        # Icône
        if hasattr(sys, '_MEIPASS'):
            icon_path = os.path.join(sys._MEIPASS, 'zonex.ico')
        else:
            icon_path = os.path.join(current_dir, 'zonex.ico')
        
        try:
            self.root.iconbitmap(icon_path)
        except:
            pass

        logging.info("📱 Initialisation de la fenêtre de login")
        
        # Container principal
        main_container = tk.Frame(self.root, bg=COLORS["bg"])
        main_container.pack(fill="both", expand=True, padx=40, pady=40)
        
        # EN-TÊTE
        header_frame = tk.Frame(main_container, bg=COLORS["bg"])
        header_frame.pack(fill="x", pady=(0, 30))
        
        tk.Label(
            header_frame,
            text="🔐 Connexion",
            font=("Segoe UI", 20, "bold"),
            bg=COLORS["bg"],
            fg=COLORS["text"]
        ).pack()
        
        tk.Label(
            header_frame,
            text="Connectez-vous à votre compte ZoneX",
            font=("Segoe UI", 9),
            bg=COLORS["bg"],
            fg=COLORS["muted"]
        ).pack(pady=(5, 0))
        
        # CHAMP EMAIL
        email_frame = tk.Frame(main_container, bg=COLORS["bg"])
        email_frame.pack(fill="x", pady=(0, 20))
        
        tk.Label(
            email_frame,
            text="📧 Email",
            font=("Segoe UI", 10, "bold"),
            bg=COLORS["bg"],
            fg=COLORS["text"]
        ).pack(anchor="w", pady=(0, 8))
        
        self.email_entry = tk.Entry(
            email_frame,
            font=("Segoe UI", 10),
            bg="white",
            fg=COLORS["text"],
            relief="solid",
            borderwidth=1,
            highlightthickness=2,
            highlightbackground="#e5e7eb",
            highlightcolor=COLORS["accent"]
        )
        self.email_entry.pack(fill="x", ipady=8)
        self.email_entry.insert(0, "")
        
        # CHAMP MOT DE PASSE
        password_frame = tk.Frame(main_container, bg=COLORS["bg"])
        password_frame.pack(fill="x", pady=(0, 10))
        
        tk.Label(
            password_frame,
            text="🔒 Mot de passe",
            font=("Segoe UI", 10, "bold"),
            bg=COLORS["bg"],
            fg=COLORS["text"]
        ).pack(anchor="w", pady=(0, 8))
        
        self.password_entry = tk.Entry(
            password_frame,
            font=("Segoe UI", 10),
            bg="white",
            fg=COLORS["text"],
            relief="solid",
            borderwidth=1,
            show="●",
            highlightthickness=2,
            highlightbackground="#e5e7eb",
            highlightcolor=COLORS["accent"]
        )
        self.password_entry.pack(fill="x", ipady=8)
        self.password_entry.insert(0, "")
        
        # CHECKBOX AFFICHER MOT DE PASSE
        show_password_frame = tk.Frame(main_container, bg=COLORS["bg"])
        show_password_frame.pack(fill="x", pady=(0, 25))
        
        self.show_password_var = tk.BooleanVar()
        show_password_check = tk.Checkbutton(
            show_password_frame,
            text="Afficher le mot de passe",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            font=("Segoe UI", 9),
            bg=COLORS["bg"],
            fg=COLORS["text"],
            selectcolor="white",
            activebackground=COLORS["bg"],
            activeforeground=COLORS["text"],
            cursor="hand2"
        )
        show_password_check.pack(anchor="w")
        
        # BOUTON CONNEXION
        self.login_button = tk.Button(
            main_container,
            text="🚀 Se connecter",
            command=self.do_login,
            bg=COLORS["accent"],
            fg="white",
            font=("Segoe UI", 11, "bold"),
            relief="flat",
            bd=0,
            cursor="hand2",
            padx=20,
            pady=12
        )
        self.login_button.pack(fill="x", pady=(0, 15))
        
        # Effets hover sur le bouton
        def on_enter(e):
            self.login_button.config(bg="#1d4ed8")

        def on_leave(e):
            self.login_button.config(bg=COLORS["accent"])

        self.login_button.bind("<Enter>", on_enter)
        self.login_button.bind("<Leave>", on_leave)
        
        # MESSAGE D'INFO
        info_frame = tk.Frame(main_container, bg="#f0f9ff", relief="solid", borderwidth=1)
        info_frame.pack(fill="x", pady=(10, 0))
        

        # Focus et validation par Entrée
        self.email_entry.focus_set()
        self.email_entry.bind("<Return>", lambda e: self.password_entry.focus_set())
        self.password_entry.bind("<Return>", lambda e: self.do_login())
    
    def toggle_password_visibility(self):
        """Affiche/cache le mot de passe"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
            logging.debug("👁️ Mot de passe visible")
        else:
            self.password_entry.config(show="●")
            logging.debug("🙈 Mot de passe caché")
        
    def do_login(self):
        """Tente de se connecter avec les identifiants fournis"""
        email = self.email_entry.get().strip()
        password = self.password_entry.get()
        
        logging.info(f"🔐 Tentative de connexion avec l'email: {email}")
        
        # Validation
        if not email or not password:
            logging.warning("❌ Tentative de connexion sans email ou mot de passe")
            messagebox.showerror("Erreur", "Email et mot de passe requis")
            return
        
        if "@" not in email:
            logging.warning("❌ Format d'email invalide")
            messagebox.showerror("Erreur", "Format d'email invalide")
            return
        
        # Désactiver le bouton pendant la connexion
        self.login_button.config(state="disabled", text="⏳ Connexion en cours...")
        self.root.update()
        
        try:
            # Authentification
            auth_data = {
                'email': email,
                'password': password
            }
            
            login_url = f"{CONFIG['HOST_server']}users/login/"
            headers = {'Content-Type': 'application/json'}
            
            logging.debug(f"🌐 Envoi requête POST vers: {login_url}")
            
            response = requests.post(
                login_url,
                json=auth_data,
                headers=headers,
                timeout=10
            )
            
            # Debug: Affiche la réponse complète
            logging.debug(f"📥 Réponse serveur ({response.status_code}): {response.text[:200]}")
            
            if response.status_code == 200:
                try:
                    response_data = response.json()
                    
                    # Version 1: Si le serveur retourne directement le token
                    if 'accessToken' in response_data:
                        logging.info(f"✅ Connexion réussie pour {email}")
                        self.handle_successful_login(response_data, email)
                        return
                    else:
                        logging.error(f"❌ Format de réponse inattendu: {response.text[:100]}")
                        messagebox.showerror("Erreur", 
                            f"Réponse serveur inattendue:\n{response.text}")
                
                except ValueError as e:
                    logging.error(f"❌ Erreur parsing JSON: {e}")
                    messagebox.showerror("Erreur", 
                        f"Format de réponse invalide:\n{response.text}")
            
            else:
                logging.warning(f"❌ Échec authentification (Code: {response.status_code})")
                messagebox.showerror("Erreur", 
                    f"Identifiants incorrects\nVeuillez réessayer")
                
        except requests.exceptions.RequestException as e:
            logging.error(f"❌ Erreur de connexion réseau: {str(e)}")
            messagebox.showerror("Erreur", f"Erreur de connexion:\n{str(e)}")
        
        finally:
            # Réactiver le bouton
            self.login_button.config(state="normal", text="🚀 Se connecter")

    def handle_successful_login(self, response_data, email):
        """Gère une connexion réussie"""
        logging.debug(f"🔑 Token reçu: {response_data['accessToken'][:20]}...")
        CONFIG['auth_token'] = response_data['accessToken']
        CONFIG['company_id'] = str(response_data.get('company', ''))
        CONFIG['user_email'] = email
        CONFIG['mqtt_topic'] = f"alert_grouped/#"
        
        logging.info(f"🏢 Company ID: {CONFIG['company_id']}")
        
        if save_config():
            logging.info("✅ Configuration sauvegardée avec succès")
            messagebox.showinfo("Succès", f"Bienvenue {email} !")
            self.root.destroy()

    def finalize_login(self, email):
        """Finalise la connexion après avoir reçu le token"""
        CONFIG['user_email'] = email
        if 'company_id' not in CONFIG:
            CONFIG['company_id'] = 'default'
        CONFIG['mqtt_topic'] = "alert_grouped/#"
        
        logging.info(f"🎯 Finalisation login pour {email}")
        
        if save_config():
            logging.info("✅ Login finalisé avec succès")
            self.root.destroy()
            show_startup_notification()

def setup_logging():
    """Configure le système de logging"""
    log_file = Path.home() / 'mqtt_notifier.log'
    logging.basicConfig(
        level=print,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def get_config_path():
    """Retourne le chemin absolu du fichier de config"""
    return Path(CONFIG['config_file']).expanduser().absolute()

def load_config():
    """Charge la configuration depuis le fichier"""
    try:
        config_path = get_config_path()
        logging.debug(f"📂 Chargement config depuis: {config_path}")
        if config_path.exists():
            with open(config_path, 'r') as f:
                saved_config = json.load(f)
                CONFIG.update(saved_config)
                if 'company_id' in saved_config:
                    CONFIG['mqtt_topic'] = f"alert_grouped/#"
            logging.info("✅ Configuration chargée avec succès")
            return True
        logging.warning("⚠️ Fichier de config non trouvé")
        return False
    except Exception as e:
        logging.error(f"❌ Erreur chargement config: {e}", exc_info=True)
        return False

def save_config():
    """Sauvegarde la configuration actuelle"""
    try:
        config_path = get_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, 'w') as f:
            json.dump({
                'company_id': CONFIG.get('company_id'),
                'auth_token': CONFIG.get('auth_token'),
                'user_email': CONFIG.get('user_email')
            }, f, indent=4)
        logging.debug(f"💾 Configuration sauvegardée dans: {config_path}")
        return True
    except Exception as e:
        logging.error(f"❌ Erreur sauvegarde config: {e}", exc_info=True)
        return False


# Cache pour les images téléchargées
image_cache = {}

def download_and_cache_image(image_url, cache_dir=None):
    """Télécharge une image et la met en cache localement"""
    try:
        if image_url in image_cache:
            logging.debug(f"📦 Image déjà en cache: {image_url}")
            return image_cache[image_url]
        
        logging.info(f"📥 Téléchargement image pour cache: {image_url}")
        
        if cache_dir is None:
            cache_dir = Path.home() / '.zonex_image_cache'
            cache_dir.mkdir(exist_ok=True)
        
        # Nettoyer le nom de fichier
        filename = image_url.split('/')[-1].split('?')[0]
        safe_filename = "".join(c for c in filename if c.isalnum() or c in ('-', '_', '.'))
        cache_path = cache_dir / safe_filename
        
        # Télécharger si pas déjà en cache local
        if not cache_path.exists():
            response = requests.get(image_url, timeout=10)
            if response.status_code == 200:
                with open(cache_path, 'wb') as f:
                    f.write(response.content)
                logging.info(f"✅ Image téléchargée: {cache_path}")
            else:
                logging.warning(f"⚠️ Impossible de télécharger l'image: {image_url}")
                return None
        
        # Charger l'image pour Tkinter
        img = Image.open(cache_path)
        img.thumbnail((35, 35))
        photo = ImageTk.PhotoImage(img)
        
        # Mettre en cache
        image_cache[image_url] = photo
        return photo
        
    except Exception as e:
        logging.error(f"❌ Erreur téléchargement cache image: {e}")
        return None



def format_duration(due_date_str, last_date_str):
    """Formate la durée entre deux dates"""
    if not due_date_str or not last_date_str:
        return ""
    
    try:
        due_date = datetime.fromisoformat(due_date_str)
        last_date = datetime.fromisoformat(last_date_str)
        total_seconds = int((last_date - due_date).total_seconds())

        if total_seconds < 0:
            return "0s"

        days, remainder = divmod(total_seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)

        parts = []
        if days:
            parts.append(f"{days}j")
        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}min")
        if seconds:
            parts.append(f"{seconds}s")

        return ', '.join(parts) if parts else "0s"
    except Exception as e:
        logging.error(f"❌ Erreur formatage durée: {e}")
        return ""


from win10toast_click import ToastNotifier
import threading
import json
from datetime import datetime
import logging
import webbrowser
import winsound
import logging

def play_alert_sound(count=1,s=""):
    """Joue UN SEUL son système peu importe le nombre d'alertes"""
    try:
        # ⭐ TOUJOURS 1 seul bip
        winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)

        logging.info(f"🔔 Son d'alerte joué (1 bip pour {count} alerte(s)) {s}")
        
    except Exception as e:
        logging.error(f"❌ Erreur lecture son: {e}")
toaster = ToastNotifier()

def show_notificationtoaster(title, message):
    """Affiche une notification Windows avec callback de clic"""
    try:
        logging.info(f"📢 Préparation notification: {title}")
        
        def on_notification_click():
            logging.info("🎯 Notification cliquée - Tentative réouverture interface")

            try:
                # Vérifie si une fenêtre Tk existe déjà
                if tk._default_root and tk._default_root.winfo_exists():
                    logging.debug("🪟 Fenêtre existante détectée, on la réaffiche")
                    tk._default_root.deiconify()
                    tk._default_root.lift()
                else:
                    logging.info("🆕 Création d'une nouvelle fenêtre principale")
                    root = tk.Tk()
                    app = MainWindow(root)
                    root.mainloop()

            except Exception as e:
                logging.error(f"❌ Erreur réouverture interface: {e}", exc_info=True)

            return 0

        # Utiliser win10toast_click qui supporte les callbacks
        toaster.show_toast(
            title=title,
            msg=message,
            icon_path=current_dir / "zonex.ico",
            duration=5,
            threaded=True,
            callback_on_click=on_notification_click
        )

        logging.info(f"✅ Notification envoyée: {title}")

    except Exception as e:
        logging.error(f"❌ Erreur notification: {e}", exc_info=True)
        
def show_notificationtoaster_list(title, alerts_list):
    """Affiche une notification Windows avec la liste des EPCs de plusieurs alertes"""
    try:
        logging.info(f"📋 Préparation notification groupée avec {len(alerts_list)} alertes")
        
        epc_list = []
        d_ids = []

        for alert in alerts_list:
            if isinstance(alert, str):
                alert = json.loads(alert)

            decl = alert.get("declanchement", {})
            epc = decl.get("epc", "N/A")
            epc_list.append(epc)

            d_id = alert.get("d_id")
            if d_id is not None:
                d_ids.append(str(d_id))

        display_msg = "EPCs:\n" + "\n".join(epc_list)
        all_d_ids = ";".join(d_ids)

        icon_path = None

        def on_click():
            logging.info(f"🎯 Notification groupée cliquée - d_ids: {all_d_ids}")
            if all_d_ids:
                threading.Thread(target=popup_form, args=(all_d_ids,), daemon=True).start()
            return 0

        toaster.show_toast(
            title=title,
            msg=display_msg,
            icon_path=icon_path,
            duration=10,
            threaded=True,
            callback_on_click=on_click
        )

        logging.info(f"✅ Notification groupée envoyée avec {len(epc_list)} EPCs et d_id={all_d_ids}")

    except Exception as e:
        logging.error(f"❌ Erreur notification groupée: {e}", exc_info=True)

import tkinter as tk
from tkinter import ttk, messagebox
import re
import requests
import logging

import tkinter as tk
from tkinter import ttk, messagebox
import re
import requests
import logging
from collections import defaultdict

import tkinter as tk
from tkinter import ttk, messagebox
import re, requests, logging

def mark_alert_as_treated(alert_id):
    """Marque une alerte comme traitée dans la liste globale"""
    global received_alerts
    logging.info(f"🏷️ Marquage alerte {alert_id} comme traitée")
    
    with alerts_lock:
        for alert in received_alerts:
            # ⭐⭐ CORRECTION : Chercher par rule_id ET par id complet
            if alert.get('rule_id') == alert_id or alert.get('id') == alert_id:
                alert['treated'] = True
                logging.info(f"✅ Alerte {alert.get('id')} (rule_id={alert_id}) marquée comme traitée")
                return True
        logging.warning(f"⚠️ Alerte {alert_id} non trouvée dans la liste")
        return False
from collections import defaultdict

def extract_epcs_and_categories(message):
    """Extrait les EPCs et les regroupe par catégorie"""
    logging.debug(f"🔍 Extraction EPCs et catégories - Type: {type(message)}")
    
    epcs = []
    categories = defaultdict(list)

    if isinstance(message, str):
        logging.debug(f"📝 Traitement format texte - Longueur: {len(message)}")
        current_category = None
        for line in message.splitlines():
            line = line.strip()
            if not line:
                continue

            if not line.startswith("-") and "(" in line and ")" in line:
                current_category = line.split("(")[0].strip()
                logging.debug(f"📂 Catégorie détectée (texte): {current_category}")

            elif line.startswith("-") and current_category:
                parts = line.split("|")
                if parts:
                    epc = parts[0].replace("-", "").strip()
                    epcs.append(epc)
                    categories[current_category].append(epc)
                    logging.debug(f"📌 EPC détecté (texte): {epc}")

    elif isinstance(message, dict):
        logging.debug(f"📊 Traitement format dict - Clés: {list(message.keys())}")
        
        if 'catagories' in message:
            categories_data = message['catagories']
            logging.debug(f"📂 Catégories directes trouvées: {len(categories_data)}")
            
            for category in categories_data:
                category_name = category.get('category_name', 'Inconnue')
                alarms = category.get('alarms', [])
                
                logging.debug(f"📦 Traitement catégorie: {category_name} ({len(alarms)} alarmes)")
                
                for alarm in alarms:
                    epc = alarm.get('epc')
                    if epc:
                        epcs.append(epc)
                        categories[category_name].append(epc)
                        logging.debug(f"📌 EPC détecté: {epc}")
        
        elif 'message' in message and isinstance(message['message'], dict):
            if 'catagories' in message['message']:
                categories_data = message['message']['catagories']
                logging.debug(f"📂 Catégories dans sous-message: {len(categories_data)}")
                
                for category in categories_data:
                    category_name = category.get('category_name', 'Inconnue')
                    alarms = category.get('alarms', [])
                    
                    logging.debug(f"📦 Traitement catégorie: {category_name} ({len(alarms)} alarmes)")
                    
                    for alarm in alarms:
                        epc = alarm.get('epc')
                        if epc:
                            epcs.append(epc)
                            categories[category_name].append(epc)
                            logging.debug(f"📌 EPC détecté: {epc}")
        
        elif 'categories' in message:
            for category in message['categories']:
                category_name = category.get('name', 'Inconnue')
                items = category.get('items', [])
                
                for item in items:
                    if 'epc' in item:
                        epcs.append(item['epc'])
                        categories[category_name].append(item['epc'])

    else:
        logging.warning(f"⚠️ Format de message non supporté: {type(message)} - Valeur: {message}")
        return [], {}

    unique_epcs = list(dict.fromkeys(epcs))
    
    logging.info(f"📊 Extraction terminée: {len(unique_epcs)} EPCs uniques, {len(categories)} catégories")
    if categories:
        logging.debug(f"📋 Catégories extraites: {list(categories.keys())}")
    
    return unique_epcs, categories

def send_alert_to_api(alert_id, status, description, epcs):
    """Envoie l'alerte traitée à l'API Django"""
    logging.info(f"🌐 Envoi alerte {alert_id} vers l'API")
    logging.debug(f"📊 Données: Statut={status}, EPCs={len(epcs)}, Description={len(description)} caractères")
    
    api_url = f"{CONFIG['HOST_server']}rules/declanchements/change_status_and_comment_descktop/"
    payload = {"rule_id": alert_id, "status": status, "description": description, "epcs": epcs}
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {CONFIG.get('auth_token', '')}"}
    
    logging.debug(f"🔗 URL API: {api_url}")
    logging.debug(f"📦 Payload: {json.dumps(payload)[:200]}...")
    
    try:
        response = requests.post(api_url, json=payload, headers=headers, timeout=10)
        logging.debug(f"📥 Réponse API: Status={response.status_code}, Body={response.text[:200]}...")
        
        if response.status_code == 201 or response.status_code == 200:
            logging.info(f"✅ Alerte {alert_id} envoyée avec succès - Statut: {status}")
            return True
        else:
            logging.warning(f"⚠️ Échec envoi alerte {alert_id}, status: {response.status_code}")
            logging.warning(f"📄 Réponse complète: {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        logging.warning(f"🌐 Pas de connexion, stockage de l'alerte {alert_id}: {e}")
        return False


# pending_queue = []

# def sync_pending_alerts(interval=30):
#     while True:
#         if pending_queue:
#             logging.info(f"🔄 Tentative de synchronisation de {len(pending_queue)} alertes en attente...")
#             for alert in pending_queue[:]:
#                 try:
#                     logging.debug(f"📤 Envoi alerte en attente ID: {alert['id']}")
#                     send_alert_to_api(alert['id'], alert['treated'], alert['description'])
#                     pending_queue.remove(alert)
#                     logging.info(f"✅ Alerte en attente {alert['id']} synchronisée")
#                 except Exception as e:
#                     logging.warning(f"🌐 Toujours pas de connexion pour {alert['id']} : {e}")
#         time.sleep(interval)

# threading.Thread(target=sync_pending_alerts, daemon=True).start()

def notification_worker():
    """Traite les notifications de la file d'attente"""
    logging.info("👷 Démarrage du worker de notifications")
    
    while True:
        item = notification_queue.get()
        logging.debug(f"📥 Élément reçu dans la file: {type(item)}")
        
        if item is None:
            logging.info("⏹️ Arrêt du worker de notifications")
            break

        with notification_lock:
            try:
                if isinstance(item, tuple) and len(item) == 2:
                    data, mqtt_topic = item
                    
                    # Ligne ~672
                    if isinstance(data, list):
                        logging.info(f"📋 Traitement d'une liste de {len(data)} règles depuis topic: {mqtt_topic}")
                        play_alert_sound(1,"list")

                        for rule_data in data:
                            if isinstance(rule_data, dict) and 'rule_id' in rule_data:
                                rule_id = rule_data.get('rule_id')
                                rule_name = rule_data.get('rule_name', 'Inconnue')
                                
                                # ⭐⭐⭐ CORRECTION : Créer un topic unique par règle
                                unique_topic = f"{mqtt_topic}_rule_{rule_id}"
                                
                                logging.debug(f"📢 Notification règle {rule_id}: {rule_name}")
                                
                                # Passer le topic unique
                                add_alert_to_list(rule_data, unique_topic)
                                
                                logging.debug(f"✅ Règle {rule_id} ajoutée avec topic: {unique_topic}")

                    elif isinstance(data, dict):
                        # Traitement pour un seul objet
                        if 'rule_id' in data:
                            add_alert_to_list(data, mqtt_topic)
                        else:
                            logging.warning(f"⚠️ Objet sans rule_id reçu: {data}")
                    else:
                        logging.warning(f"⚠️ Format de données inattendu: {type(data)}")
                        
                elif isinstance(item, dict):
                    # Gestion rétrocompatible (format ancien sans topic)
                    logging.warning("⚠️ Format ancien détecté (sans topic)")
                    if 'rule_id' in item:
                        title = f"La Règle {item.get('rule_name', 'Inconnue')} a été violée par"
                        message = build_notification_message(item)
                        show_notificationtoaster(title, message)
                        play_alert_sound(1,"dict")

                        add_alert_to_list(item, "topic_inconnu")
                    else:
                        logging.warning("⚠️ Objet sans rule_id dans format ancien")
                        
                elif isinstance(item, list):
                    # Gestion rétrocompatible pour les listes
                    logging.warning("⚠️ Format ancien liste détecté (sans topic)")
                    for alert in item:
                        if isinstance(alert, dict) and 'rule_id' in alert:
                            add_alert_to_list(alert, "topic_inconnu")
                        else:
                            logging.warning(f"⚠️ Élément non valide dans liste ancienne: {type(alert)}")
                            
            except Exception as e:
                logging.error(f"❌ Erreur affichage notification: {e}", exc_info=True)

        time.sleep(1)
        notification_queue.task_done()
import time
import time
from datetime import datetime

def add_alert_to_list(payload, mqtt_topic=None):
    """Ajoute ou met à jour une alerte - REGROUPE par rule_id avec dédoublonnage strict"""
    try:
        logging.info(f"📝 Ajout alerte à la liste - Topic: {mqtt_topic}")
        
        with alerts_lock:
            global received_alerts

            if isinstance(payload, dict):
                rule_id = payload.get('rule_id')
                rule_name = payload.get('rule_name', 'Inconnue')
                
                # ⭐⭐⭐ CORRECTION : Chercher par rule_id MAIS IGNORER les alertes traitées
                existing_index = -1
                old_alert = None
                for i, alert in enumerate(received_alerts):
                    # ✅ MODIFICATION CRITIQUE : Ajouter "and not alert.get('treated', False)"
                    if alert.get('rule_id') == rule_id and not alert.get('treated', False):
                        existing_index = i
                        old_alert = alert
                        logging.info(f"📌 Alerte active trouvée: {rule_id} (ID: {alert.get('id')})")
                        break
                
                # === EXTRACTION DES DONNÉES ===
                doors_dict = {}
                all_timestamps = []
                readers_set = set() 
                categories = payload.get('catagories', [])
                for category in categories:
                    category_id = category.get('category_id')
                    category_name = category.get('category_name', 'Inconnue')
                    category_icon = category.get('category_icon', '')
                    
                    for alarm in category.get('alarms', []):
                        alarm_timestamp = alarm.get('timestamp')
                        if alarm_timestamp:
                            all_timestamps.append(alarm_timestamp)
                        
                        door_id = alarm.get('door_id')
                        reader_serial = alarm.get('reader', 'unknown')
                        readers_set.add(reader_serial)  # ⭐ COLLECTER

                        door_name = alarm.get('door_name', f'Porte {door_id}')
                        zone_name = alarm.get('zone_name', 'Zone inconnue')
                        
                        door_key = f"{door_id}_{reader_serial}"
                        
                        # ✅ CRÉER OU METTRE À JOUR
                        if door_key not in doors_dict:
                            doors_dict[door_key] = {
                                'door_info': {
                                    'door_id': door_id,
                                    'door_name': door_name,
                                    'reader': reader_serial,
                                    'zone_name': zone_name
                                },
                                'categories': {}
                            }
                        
                        # ✅ AJOUTER CATÉGORIE si inexistante
                        if category_id not in doors_dict[door_key]['categories']:
                            doors_dict[door_key]['categories'][category_id] = {
                                'category_id': category_id,
                                'category_name': category_name,
                                'category_icon': category_icon,
                                'alarms': []
                            }
                        
                        # ⭐⭐⭐ CRITIQUE : Vérification doublon STRICTE (EPC + Timestamp)
                        # ⭐⭐⭐ MODIFICATION : Garder toujours le DERNIER timestamp pour chaque EPC
                        new_epc = alarm.get('epc')
                        new_timestamp = alarm.get('timestamp')

                        # Chercher si cet EPC existe déjà
                        existing_alarms = doors_dict[door_key]['categories'][category_id]['alarms']
                        existing_alarm_index = -1

                        for i, existing_alarm in enumerate(existing_alarms):
                            if existing_alarm.get('epc') == new_epc:
                                existing_alarm_index = i
                                break

                        if existing_alarm_index >= 0:
                            # ⭐⭐ METTRE À JOUR avec le timestamp le plus récent
                            existing_timestamp = existing_alarms[existing_alarm_index].get('timestamp', '')
                            
                            try:
                                # Comparer les dates pour garder le plus récent
                                new_dt = datetime.strptime(new_timestamp, '%Y-%m-%d %H:%M:%S')
                                existing_dt = datetime.strptime(existing_timestamp, '%Y-%m-%d %H:%M:%S')
                                
                                if new_dt > existing_dt:  # Nouveau timestamp est plus récent
                                    existing_alarms[existing_alarm_index] = alarm  # Remplacer
                                    logging.debug(f"🔄 Mise à jour EPC {new_epc}: {existing_timestamp} → {new_timestamp}")
                                else:
                                    logging.debug(f"🔄 Ancien timestamp gardé pour EPC {new_epc}: {existing_timestamp} > {new_timestamp}")
                            except Exception as e:
                                # En cas d'erreur de parsing, on remplace
                                logging.warning(f"⚠️ Erreur comparaison timestamps: {e}")
                                existing_alarms[existing_alarm_index] = alarm
                        else:
                            # Nouvel EPC - on l'ajoute
                            existing_alarms.append(alarm)
                            logging.debug(f"➕ Nouvel EPC ajouté: {new_epc} @ {new_timestamp}")
                
                # Timestamp le plus récent
                latest_timestamp = None
                for ts in all_timestamps:
                    try:
                        ts_dt = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
                        if not latest_timestamp or ts_dt > datetime.strptime(latest_timestamp, '%Y-%m-%d %H:%M:%S'):
                            latest_timestamp = ts
                    except:
                        continue
                
                # === LOGIQUE DE MISE À JOUR ===
                if existing_index >= 0:
                    # ⭐⭐ ALERTE EXISTANTE : FUSIONNER avec dédoublonnage
                    was_treated = old_alert.get('treated', False)
                    alert_id = old_alert.get('id')
                    
                    logging.info(f"🔄 Fusion alerte {alert_id}")
                    
                    # Récupérer les anciennes portes
                    existing_doors = old_alert.get('message', {}).get('doors', {})
                                        # ⭐ COLLECTER readers existants
                    existing_readers = old_alert.get('readers', set())
                    if isinstance(existing_readers, list):
                        existing_readers = set(existing_readers)
                    existing_readers.update(readers_set)  # FUSIONNER
                    logging.debug(f"📂 Portes avant: {list(existing_doors.keys())}")
                    
                    # ⭐⭐⭐ FUSIONNER avec dédoublonnage strict
                    for door_key, door_data in doors_dict.items():
                        if door_key in existing_doors:
                            logging.debug(f"🔀 Fusion porte: {door_key}")
                            
                            # Fusionner catégories
                            for cat_id, cat_data in door_data['categories'].items():
                                existing_cats = existing_doors[door_key]['categories']
                                
                                # Chercher catégorie existante
                                existing_cat = None
                                for ec in existing_cats:
                                    if ec.get('category_id') == cat_id:
                                        existing_cat = ec
                                        break
                                
                                if existing_cat:
                                    # ⭐⭐⭐ FUSION ALARMES avec dédoublonnage
                                    # ⭐⭐⭐ FUSION ALARMES en gardant le DERNIER timestamp
                                    before_count = len(existing_cat['alarms'])

                                    for new_alarm in cat_data['alarms']:
                                        new_epc = new_alarm.get('epc')
                                        new_timestamp = new_alarm.get('timestamp')
                                        
                                        # Chercher si cet EPC existe déjà
                                        existing_alarm_index = -1
                                        for i, existing_alarm in enumerate(existing_cat['alarms']):
                                            if existing_alarm.get('epc') == new_epc:
                                                existing_alarm_index = i
                                                break
                                        
                                        if existing_alarm_index >= 0:
                                            # ⭐⭐ METTRE À JOUR avec le timestamp le plus récent
                                            existing_timestamp = existing_cat['alarms'][existing_alarm_index].get('timestamp', '')
                                            
                                            try:
                                                new_dt = datetime.strptime(new_timestamp, '%Y-%m-%d %H:%M:%S')
                                                existing_dt = datetime.strptime(existing_timestamp, '%Y-%m-%d %H:%M:%S')
                                                
                                                if new_dt > existing_dt:
                                                    existing_cat['alarms'][existing_alarm_index] = new_alarm
                                                    logging.debug(f"  🔄 Mise à jour: {new_epc} {existing_timestamp} → {new_timestamp}")
                                                else:
                                                    logging.debug(f"  🔄 Gardé ancien: {new_epc} {existing_timestamp}")
                                            except:
                                                # En cas d'erreur, on remplace
                                                existing_cat['alarms'][existing_alarm_index] = new_alarm
                                        else:
                                            # Nouvel EPC
                                            existing_cat['alarms'].append(new_alarm)
                                            logging.debug(f"  ➕ Ajout: {new_epc} @ {new_timestamp}")
                                else:
                                    # Nouvelle catégorie
                                    existing_cats.append(cat_data)
                                    logging.debug(f"  ➕ Nouvelle catégorie: {cat_data.get('category_name')}")
                        else:
                            # Nouvelle porte
                            logging.info(f"➕ Nouvelle porte: {door_key}")
                            existing_doors[door_key] = {
                                'door_info': door_data['door_info'],
                                'categories': list(door_data['categories'].values())
                            }
                    
                    logging.debug(f"📂 Portes après: {list(existing_doors.keys())}")
                    
                    # Mettre à jour timestamp
                    current_ts = old_alert.get('timestamp', '')
                    if latest_timestamp:
                        try:
                            if not current_ts or datetime.strptime(latest_timestamp, '%Y-%m-%d %H:%M:%S') > datetime.strptime(current_ts, '%Y-%m-%d %H:%M:%S'):
                                old_alert['timestamp'] = latest_timestamp
                                logging.info(f"⏰ Timestamp: {current_ts} → {latest_timestamp}")
                        except:
                            old_alert['timestamp'] = latest_timestamp
                    
                    # ⭐⭐⭐ STOCKER LA LISTE DES READERS
                    old_alert['readers'] = list(existing_readers)
                    # ⭐⭐⭐ FORCER mise à jour
                    received_alerts[existing_index] = old_alert
                    
                    # Compter total alarmes
                    total_alarms = sum(
                        len(cat['alarms'])
                        for door in existing_doors.values()
                        for cat in door['categories']
                    )
                    
                    logging.info(f"✅ Alerte {alert_id} fusionnée : {len(existing_doors)} portes, {total_alarms} alarmes")
                    
                else:
                    # ⭐⭐ NOUVELLE ALERTE
                    alert_id = f"rule_{rule_id}_{int(time.time() * 1000)}"
                    
                    new_alert = {
                        'id': alert_id,
                        'rule_id': rule_id,
                        'rule_name': rule_name,
                        'timestamp': latest_timestamp or datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'topic': mqtt_topic,
                        'title': f"📋 {rule_name}",
                        'readers': list(readers_set),
                        'message': {
                            'rule_id': rule_id,
                            'rule_name': rule_name,
                            'doors': {}
                        },
                        'treated': False
                    }
                    
                    for door_key, door_data in doors_dict.items():
                        new_alert['message']['doors'][door_key] = {
                            'door_info': door_data['door_info'],
                            'categories': list(door_data['categories'].values())
                        }
                    
                    # Compter alarmes
                    total_alarms = sum(
                        len(cat['alarms'])
                        for door in new_alert['message']['doors'].values()
                        for cat in door['categories']
                    )
                    
                    received_alerts.append(new_alert)
                    logging.info(f"✅ Nouvelle alerte: {alert_id} - {len(new_alert['message']['doors'])} portes, {total_alarms} alarmes")
                
                # Limiter taille
                MAX_ALERTS = 50
                if len(received_alerts) > MAX_ALERTS:
                    received_alerts = sorted(
                        received_alerts,
                        key=lambda x: (0 if not x.get('treated') else 1, x.get('timestamp', '')),
                        reverse=True
                    )[:MAX_ALERTS]
                
                logging.info(f"📊 Total alertes en mémoire: {len(received_alerts)}")
                
                # Mettre à jour UI (debounced)
                if hasattr(main_window, 'update_alerts_list'):
                    if hasattr(main_window, '_update_timer'):
                        try:
                            main_window.root.after_cancel(main_window._update_timer)
                        except:
                            pass
                    
                    main_window._update_timer = main_window.root.after(200, lambda: [
                        main_window.update_alerts_list(),
                        bring_window_to_front_enhanced(main_window.root)
                    ])
                    
    except Exception as e:
        logging.error(f"❌ Erreur ajout alerte: {e}", exc_info=True)


def get_full_image_url(icon_path):
    """Construit l'URL complète d'une icône"""
    if not icon_path:
        return None
    
    if icon_path.startswith('http'):
        return icon_path
    
    base_url = CONFIG['HOST_server'].replace('/api', '/media')
    if icon_path.startswith('/'):
        return base_url + icon_path
    else:
        return base_url + '/' + icon_path

def extract_latest_timestamp_from_payload(payload):
    """Extrait le timestamp le plus récent du payload"""
    try:
        logging.debug("🔍 Extraction du timestamp le plus récent")
        all_timestamps = []
        
        for rule in payload if isinstance(payload, list) else [payload]:
            for category in rule.get("catagories", []):
                for alarm in category.get("alarms", []):
                    if "timestamp" in alarm:
                        all_timestamps.append(alarm["timestamp"])
        
        logging.debug(f"📊 {len(all_timestamps)} timestamps trouvés")
        
        if all_timestamps:
            datetime_objects = [datetime.strptime(ts, '%Y-%m-%d %H:%M:%S') for ts in all_timestamps]
            latest_timestamp = max(datetime_objects)
            result = latest_timestamp.strftime('%Y-%m-%d %H:%M:%S')
            logging.debug(f"⏰ Timestamp le plus récent: {result}")
            return result
        else:
            result = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            logging.warning(f"⚠️ Aucun timestamp trouvé, utilisation timestamp actuel: {result}")
            return result
            
    except Exception as e:
        logging.error(f"❌ Erreur extraction timestamp: {e}", exc_info=True)
        result = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return result

import ctypes
import win32gui
import win32con
import win32process
import win32api
import time

def bring_window_to_front_enhanced(window):
    """Force une fenêtre Tkinter à s'afficher au premier plan"""
    logging.info("🪟 Tentative de mise au premier plan de la fenêtre")
    
    try:
        hwnd = window.winfo_id()
        logging.debug(f"🆔 Handle fenêtre: {hwnd}")
        
        # Restaurer si minimisée
        try:
            if win32gui.IsIconic(hwnd):
                logging.debug("📂 Fenêtre minimisée - restauration")
                win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                time.sleep(0.05)
        except:
            pass
        
        # Deiconify et maximiser via Tkinter
        window.deiconify()
        window.state('zoomed')
        logging.debug("🖥️ Fenêtre maximisée")
        
        # Autoriser SetForegroundWindow
        try:
            ASFW_ANY = -1
            ctypes.windll.user32.AllowSetForegroundWindow(ASFW_ANY)
        except:
            pass
        
        # Attachement des threads
        fg_thread = None
        app_thread = None
        try:
            foreground_hwnd = win32gui.GetForegroundWindow()
            if foreground_hwnd and foreground_hwnd != hwnd:
                fg_thread, _ = win32process.GetWindowThreadProcessId(foreground_hwnd)
                app_thread = win32api.GetCurrentThreadId()
                
                if fg_thread != app_thread:
                    logging.debug(f"🧵 Attachement threads: {fg_thread} -> {app_thread}")
                    ctypes.windll.user32.AttachThreadInput(fg_thread, app_thread, True)
                    time.sleep(0.02)
        except Exception as e:
            logging.debug(f"⚠️ Attachement threads ignoré: {e}")
        
        # Mettre en TOPMOST temporairement
        try:
            win32gui.SetWindowPos(
                hwnd, 
                win32con.HWND_TOPMOST,
                0, 0, 0, 0,
                win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_SHOWWINDOW
            )
            logging.debug("🔝 Fenêtre en mode TOPMOST")
        except:
            pass
        
        # Maximiser via Win32
        try:
            win32gui.ShowWindow(hwnd, win32con.SW_MAXIMIZE)
        except:
            pass
        
        # Tenter SetForegroundWindow (peut échouer silencieusement)
        try:
            win32gui.SetForegroundWindow(hwnd)
            logging.debug("✅ SetForegroundWindow réussi")
        except Exception as e:
            logging.debug(f"⚠️ SetForegroundWindow échoué (normal sous Windows): {e}")
            # Ce n'est pas grave, on continue avec d'autres méthodes
        
        # BringWindowToTop comme alternative
        try:
            win32gui.BringWindowToTop(hwnd)
            logging.debug("🎯 BringWindowToTop exécuté")
        except:
            pass
        
        # Retirer TOPMOST après un délai
        def remove_topmost():
            try:
                win32gui.SetWindowPos(
                    hwnd,
                    win32con.HWND_NOTOPMOST,
                    0, 0, 0, 0,
                    win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_SHOWWINDOW
                )
            except:
                pass
        
        window.after(200, remove_topmost)
        
        # Détacher les threads
        try:
            if fg_thread and app_thread and fg_thread != app_thread:
                ctypes.windll.user32.AttachThreadInput(fg_thread, app_thread, False)
                logging.debug("🧵 Détachement threads")
        except:
            pass
        
        # Méthodes Tkinter supplémentaires
        try:
            window.focus_force()
            window.attributes('-topmost', True)
            window.after(200, lambda: window.attributes('-topmost', False))
        except:
            pass
        
        logging.info("✅ Fenêtre mise au premier plan (méthodes appliquées)")
        
    except Exception as e:
        logging.warning(f"⚠️ Erreur bring_window_to_front_enhanced: {e}")
        # Fallback simple
        try:
            window.deiconify()
            window.state('zoomed')
            window.lift()
            window.focus_force()
            logging.info("🔄 Fallback simple exécuté")
        except Exception as e2:
            logging.warning(f"⚠️ Erreur fallback: {e2}")

def build_notification_message(rule):
    """Construit le message de notification groupé"""
    try:
        logging.debug("📝 Construction message notification")
        
        message_parts = []
        
        categories = rule.get('catagories', [])
            
        category_counts = []
        for category in categories:
            if isinstance(category, dict):
                category_name = category.get('category_name', 'Catégorie inconnue')
                
                alarms = category.get('alarms', [])
                epc_count = len(alarms) if isinstance(alarms, list) else 0
                if epc_count > 0:
                    category_counts.append(f"{epc_count} {category_name}")
        
        logging.debug(f"📊 {len(category_counts)} catégories avec alertes")
        
        if category_counts:
            message_parts.append("\n".join(category_counts))
        
        result = "\n\n".join(message_parts) if message_parts else "Aucune alerte détaillée"
        logging.debug(f"📄 Message construit: {result[:100]}...")
        
        return result
        
    except Exception as e:
        logging.error(f"❌ Erreur construction message: {e}", exc_info=True)
        return "Erreur dans le format des données"


def show_notification(title, message):
    """Affiche une notification Windows avec le format corrigé"""
    try:
        logging.info(f"📢 Préparation notification Windows: {title}")
        
        notification_args = {
            "app_id": f"{CONFIG['app_name']}",
            "title": title,
            "msg": message,
            "duration": "long"
        }

        dashboard_url = CONFIG['HOST_server'].replace('/api', '')

        toast = Notification(**notification_args)
        toast.add_actions(label="Ouvrir le Dashboard", launch=dashboard_url)
        toast.show()

        logging.info(f"✅ Notification envoyée: {title}")

    except Exception as e:
        logging.error(f"❌ Erreur notification: {e}", exc_info=True)


def build_notification_message_to_list(rule):
    """Construit un message regroupé par catégorie avec les EPC, zone et timestamp"""
    try:
        logging.debug("📝 Construction message pour liste")
        
        lines = []
        categories = rule.get('catagories', [])

        for cat in categories:
            cat_name = cat.get('category_name', 'Inconnue')
            alarms = cat.get('alarms', [])

            lines.append(f"{cat_name} ({len(alarms)})")
            logging.debug(f"📂 Catégorie: {cat_name} avec {len(alarms)} alarmes")

            for alarm in alarms:
                epc = alarm.get('epc', '—')
                ts = alarm.get('timestamp', '—')
                zone = alarm.get('zone', '—')
                lines.append(f"   - {epc} | {ts}")

            lines.append("")

        result = "\n".join(lines).strip() if lines else "Aucun détail"
        logging.debug(f"📄 Message construit ({len(result)} caractères): {result[:100]}...")
        
        return result

    except Exception as e:
        logging.error(f"❌ Erreur build_notification_message_to_list: {e}", exc_info=True)
        return "Erreur format alerte"


def stop_notification_worker():
    """Arrête proprement le worker de notifications"""
    logging.info("🛑 Arrêt du worker de notifications")
    notification_queue.put(None)
    notification_thread.join()
    logging.info("✅ Worker de notifications arrêté")


def add_to_startup(name: str, exe_path: str = None):
    """Ajoute l'application au démarrage automatique de Windows"""
    if exe_path is None:
        exe_path = sys.executable
    
    logging.info(f"⚙️ Tentative d'ajout au démarrage: {name}")
    logging.debug(f"📂 Chemin exécutable: {exe_path}")
    
    try:
        reg_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_key, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, exe_path)
            logging.info(f"✅ '{name}' ajouté au démarrage automatique : {exe_path}")
    except Exception as e:
        logging.error(f"❌ Erreur lors de l'ajout au démarrage : {e}")

def show_startup_notification():
    """Affiche une notification de démarrage avec ou sans icône (si trouvée)"""
    try:
        logging.info("🔄 Initialisation de la notification de démarrage...")
        icon_path = None

        logging.debug("🔍 Recherche de l'icône...")

        local_icon = current_dir / "zonex.png"
        if local_icon.exists():
            icon_path = str(local_icon)
            logging.info(f"✅ Icône demarrage trouvée localement : {icon_path}")
        elif CONFIG.get('icon_path') and Path(CONFIG['icon_path']).exists():
            icon_path = CONFIG['icon_path']
            logging.info(f"✅ Icône demarrage trouvée via CONFIG : {icon_path}")
        else:
            default_icon = Path.home() / "notifier_icon.png"
            if default_icon.exists():
                icon_path = str(default_icon)
                logging.info(f"✅ Icône demarrage par défaut trouvée : {icon_path}")
            else:
                logging.warning("ℹ️ Aucune icône demarrage trouvée, la notification sera affichée sans icône.")

        toaster.show_toast(
            title="✅ Programme lancé",
            msg=f"Prêt à recevoir des alertes",
            icon_path=current_dir / "zonex.ico",
            duration=3,
            threaded=True,
        )

        logging.info(f"✅ Notification démarrage envoyée (icône: {icon_path})")

    except Exception as e:
        logging.error(f"❌ Erreur notification démarrage: {str(e)}", exc_info=True)


import tkinter as tk
from tkinter import ttk
import requests

import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
from datetime import datetime
import logging, os, sys
from pathlib import Path

# =====================================================
# UI THEME – LIGHT MODE
# =====================================================
COLORS = {
    "bg": "#f5f7fb",
    "card": "#ffffff",
    "border": "#e5e7eb",
    "text": "#111827",
    "muted": "#6b7280",
    "accent": "#2563eb",
    "success": "#16a34a",
    "warning": "#d97706",
    "danger": "#dc2626",
}

BASE_FONT = ("Segoe UI", 10)
TITLE_FONT = ("Segoe UI", 14, "bold")
SECTION_FONT = ("Segoe UI", 11, "bold")
SMALL_FONT = ("Segoe UI", 9)
MONO_FONT = ("Consolas", 9)

# =====================================================
# BADGE DEFINITIONS (ICON + TEXT)
# =====================================================
BADGES = {
    "critical": ("🔴", "Critique"),
    "warning": ("🟠", "Attention"),
    "info": ("🔵", "Info"),
    "treated": ("✅", "Traitée"),
}

# =====================================================
# SCROLLBAR STYLE
# =====================================================
def configure_scrollbar_style():
    style = ttk.Style()
    style.configure(
        "Modern.Vertical.TScrollbar",
        gripcount=0,
        background="#d1d5db",
        darkcolor="#d1d5db",
        lightcolor="#d1d5db",
        troughcolor=COLORS["bg"],
        bordercolor=COLORS["bg"],
        arrowcolor="#6b7280",
        width=10,
    )
    style.map(
        "Modern.Vertical.TScrollbar",
        background=[("active", "#9ca3af")]
    )


class MainWindow:
    """Interface principale - Style moderne + Logique complète du code fonctionnel"""
    
    def __init__(self, root=None):
        logging.info("🏗️ Initialisation de la fenêtre principale")
        
        self.root = root or tk.Tk()
        self.root.title(f"{CONFIG['app_name']} - Tableau de bord")
        self.root.state('zoomed')
        self.root.configure(bg=COLORS["bg"])
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Icon
        if hasattr(sys, '_MEIPASS'):
            icon_path = os.path.join(sys._MEIPASS, 'zonex.ico')
        else:
            current_dir = os.path.dirname(__file__) if '__file__' in globals() else os.getcwd()
            icon_path = os.path.join(current_dir, 'zonex.ico')
        if os.path.exists(icon_path):
            self.root.iconbitmap(icon_path)

        logging.debug("🎨 Configuration du style moderne")

        # Styles
        style = ttk.Style()
        style.theme_use("default")
        style.configure(".", font=BASE_FONT)
        style.configure("Title.TLabel", font=TITLE_FONT, background=COLORS["card"])
        style.configure("Section.TLabel", font=SECTION_FONT, background=COLORS["card"])
        style.configure("Muted.TLabel", foreground=COLORS["muted"], background=COLORS["card"])
        style.configure(
            "Accent.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(14, 8)
        )

        configure_scrollbar_style()

        # =================================================
        # TOP BAR
        # =================================================
        topbar = tk.Frame(self.root, bg=COLORS["card"], height=56)
        topbar.pack(fill="x")

        # Logo
        is_exe = hasattr(sys, '_MEIPASS')
        current_diri = Path(sys._MEIPASS) if is_exe else Path(__file__).parent
        image_path = current_diri / "zonex.png"

        if image_path.exists():
            try:
                image = Image.open(image_path)
                image = image.resize((32, 32))
                zone_image = ImageTk.PhotoImage(image)
                label_zone = tk.Label(topbar, image=zone_image, bg=COLORS["card"])
                label_zone.pack(side="left", padx=(20, 10))
                label_zone.image = zone_image
            except Exception as e:
                logging.warning(f"Logo non chargé: {e}")

        ttk.Label(topbar, text=CONFIG["app_name"], style="Title.TLabel").pack(side="left")

        ttk.Label(
            topbar,
            text=f"Utilisateur : {CONFIG.get('user_email','')}",
            style="Muted.TLabel"
        ).pack(side="left", expand=True, padx=20)

        # Statut en premier (à droite)
        self.mqtt_status = tk.StringVar(value="🔴 Déconnecté")
        self.status_label = ttk.Label(
            topbar,
            textvariable=self.mqtt_status,
            foreground=COLORS["danger"],
            background=COLORS["card"],
            font=("Segoe UI", 11, "bold")
        )
        self.status_label.pack(side="right", padx=(0, 20))

        # Label "Statut Connexion :" en second (donc à gauche du statut)
        ttk.Label(
            topbar,
            text="Statut Connexion :",
            style="Muted.TLabel"
        ).pack(side="right", padx=(20, 5))

        tk.Frame(self.root, height=1, bg=COLORS["border"]).pack(fill="x")

        # =================================================
        # MAIN LAYOUT
        # =================================================
        content = tk.Frame(self.root, bg=COLORS["bg"])
        content.pack(fill="both", expand=True, padx=16, pady=16)

        paned = ttk.PanedWindow(content, orient=tk.HORIZONTAL)
        paned.pack(fill="both", expand=True)

        # =================================================
        # LEFT – ALERTS avec scrollbar dynamique
        # =================================================
        self.left_panel = tk.Frame(paned, bg=COLORS["card"])
        paned.add(self.left_panel, weight=1)

        ttk.Label(self.left_panel, text="🚨 Alertes Reçues", style="Section.TLabel").pack(
            anchor="w", padx=16, pady=(16, 4)
        )
        ttk.Label(self.left_panel, text="Alertes en temps réel", style="Muted.TLabel").pack(
            anchor="w", padx=16, pady=(0, 8)
        )

        # Container pour canvas + scrollbar
        alerts_container = tk.Frame(self.left_panel, bg=COLORS["card"])
        alerts_container.pack(fill="both", expand=True, padx=8, pady=8)

        self.canvas = tk.Canvas(alerts_container, bg=COLORS["card"], highlightthickness=0)
        
        # ⭐ Scrollbar stockée comme attribut pour pouvoir la masquer/afficher
        self.scrollbar = ttk.Scrollbar(
            alerts_container,
            orient="vertical",
            style="Modern.Vertical.TScrollbar",
            command=self.canvas.yview
        )

        self.scrollable_alerts_frame = tk.Frame(self.canvas, bg=COLORS["card"])
        
        # ⭐ CRITIQUE: Largeur dynamique
        self.canvas_window = self.canvas.create_window(
            (0, 0), window=self.scrollable_alerts_frame, anchor="nw"
        )
        
        def on_canvas_configure(event):
            """Forcer le frame interne à prendre toute la largeur du canvas"""
            self.canvas.itemconfig(self.canvas_window, width=event.width)
        
        self.canvas.bind('<Configure>', on_canvas_configure)
        
        # ⭐ MODIFICATION CRITIQUE : Fonction qui vérifie si scrollbar nécessaire
        def update_scrollbar_visibility(event=None):
            """Affiche/masque la scrollbar selon le besoin"""
            # Mise à jour de la région scrollable
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
            
            # Attendre que le layout soit finalisé
            self.canvas.update_idletasks()
            
            # Récupérer les dimensions
            canvas_height = self.canvas.winfo_height()
            content_height = self.scrollable_alerts_frame.winfo_reqheight()
            
            # Marge de sécurité pour éviter les flickering
            MARGIN = 5
            
            # Afficher scrollbar seulement si contenu > canvas
            if content_height > (canvas_height + MARGIN):
                # Afficher la scrollbar
                if not self.scrollbar.winfo_ismapped():
                    self.scrollbar.pack(side="right", fill="y")
            else:
                # Masquer la scrollbar
                if self.scrollbar.winfo_ismapped():
                    self.scrollbar.pack_forget()
        
        self.scrollable_alerts_frame.bind("<Configure>", update_scrollbar_visibility)

        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Affichage initial du canvas (scrollbar sera ajoutée dynamiquement si besoin)
        self.canvas.pack(side="left", fill="both", expand=True)
        # Note: scrollbar.pack() sera appelé dynamiquement par update_scrollbar_visibility()

        # Mouse wheel scrolling
        def on_mousewheel(event):
            self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        self.canvas.bind_all("<MouseWheel>", on_mousewheel)

        # =================================================
        # RIGHT – FORM
        # =================================================
        self.form_container = tk.Frame(paned, bg=COLORS["card"])
        paned.add(self.form_container, weight=1)

        ttk.Label(
            self.form_container,
            text="📝 Formulaire de Traitement",
            style="Section.TLabel"
        ).pack(anchor="w", padx=16, pady=(16, 8))

        self.default_form_message = ttk.Label(
            self.form_container,
            text="Sélectionnez une alerte pour la traiter",
            style="Muted.TLabel"
        )
        self.default_form_message.pack(expand=True)

        # Internal state
        self.current_alert_id = None
        self.form_is_active = False
        self.current_form_data = {}
        self.current_form_widgets = {}

        logging.info("✅ Fenêtre principale initialisée avec succès")

    # =================================================
    # ALERT WIDGET - COMPLET avec toutes les portes
    # =================================================
    def create_alert_widget(self, alert):
        """Crée un widget d'alerte COMPLET avec style moderne et bordures arrondies"""
        rule_id = alert.get('rule_id', 'N/A')
        rule_name = alert.get('rule_name', 'Règle inconnue')
        timestamp = alert.get('timestamp', '—')
        message_content = alert.get('message', {})
        
        # Récupérer toutes les portes
        all_doors = message_content.get('doors', {})
        
        # Badge
        badge_type = "critical" if not alert.get('treated') else "treated"
        icon, badge_text = BADGES[badge_type]
        badge_bg = "#fee2e2" if badge_type == "critical" else "#dcfce7"
        badge_fg = COLORS["danger"] if badge_type == "critical" else COLORS["success"]
        
        # ⭐ Container avec effet d'ombre subtile
        alert_outer = tk.Frame(
            self.scrollable_alerts_frame,
            bg=COLORS["bg"],
            highlightthickness=0,
            bd=0
        )
        alert_outer.pack(fill="both", expand=True, padx=16, pady=6)
        
        # Frame d'ombre (effet drop-shadow)
        shadow_frame = tk.Frame(
            alert_outer,
            bg="#d1d5db",
            highlightthickness=0
        )
        shadow_frame.pack(fill="both", expand=True, padx=(2, 0), pady=(2, 0))
        
        # ⭐ Card principale avec fond blanc et bordure subtile
        card = tk.Frame(
            shadow_frame,
            bg="white",
            highlightbackground="#e5e7eb",
            highlightthickness=1,
            relief="flat"
        )
        card.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))

        # ===================
        # HEADER
        # ===================
        header = tk.Frame(card, bg="white")
        header.pack(fill="x", padx=16, pady=(12, 8))

        # LEFT
        left_container = tk.Frame(header, bg="white")
        left_container.pack(side="left", anchor="w")
        
        tk.Label(left_container, text="📋", font=("Segoe UI", 13), bg="white").pack(side="left", padx=(0, 6))
        tk.Label(left_container, text=f"{rule_name}", font=("Segoe UI", 11, "bold"), 
                bg="white", fg="#1f2937").pack(side="left")

        # RIGHT
        right_container = tk.Frame(header, bg="white")
        right_container.pack(side="right", anchor="e")
        
        tk.Label(right_container, text="⏰", font=("Segoe UI", 10), bg="white").pack(side="left", padx=(0, 3))
        tk.Label(right_container, text=timestamp, font=SMALL_FONT, bg="white", 
                fg=COLORS["muted"]).pack(side="left", padx=(0, 10))
        
        # Badge avec coins arrondis simulés
        badge_frame = tk.Frame(right_container, bg="white")
        badge_frame.pack(side="left", padx=(0, 10))
        
        tk.Label(badge_frame, text=f"{icon} {badge_text}", font=("Segoe UI", 9, "bold"),
                bg=badge_bg, fg=badge_fg, padx=8, pady=2).pack()

        # Portes/readers count
        unique_door_ids = set()
        total_readers = len(all_doors)
        for door_data in all_doors.values():
            door_id = door_data.get("door_info", {}).get("door_id")
            if door_id:
                unique_door_ids.add(door_id)
        unique_doors_count = len(unique_door_ids)
        
        tk.Label(right_container, 
                text=f"📍 {unique_doors_count} porte{'s' if unique_doors_count > 1 else ''} • {total_readers} reader{'s' if total_readers > 1 else ''}",
                font=("Segoe UI", 9, "italic"), bg="white", fg=COLORS["muted"]).pack(side="left")

        # Séparateur
        tk.Frame(card, height=1, bg="#e5e7eb").pack(fill="x", padx=16, pady=(0, 8))

        # ===================
        # LISTE COMPLÈTE DES PORTES
        # ===================
        if all_doors:
            for door_key, door_data in all_doors.items():
                door_info = door_data.get('door_info', {})
                categories = door_data.get('categories', [])
                
                door_name = door_info.get('door_name', 'Porte inconnue')
                reader_serial = door_info.get('reader', 'N/A')
                zone_name = door_info.get('zone_name', 'Zone inconnue')
                
                # Cadre porte avec bordure subtile
                porte_frame = tk.Frame(card, bg="#f9fafb", relief="flat", 
                                    highlightbackground="#e5e7eb", highlightthickness=1)
                porte_frame.pack(fill="x", padx=16, pady=(0, 10))
                
                # En-tête porte
                porte_header = tk.Frame(porte_frame, bg="#dbeafe")
                porte_header.pack(fill="x", padx=8, pady=6)
                
                tk.Label(porte_header, text="🚪", font=("Segoe UI", 11), bg="#dbeafe").pack(side="left", padx=(0, 6))
                
                info_frame = tk.Frame(porte_header, bg="#dbeafe")
                info_frame.pack(side="left", fill="x", expand=True)
                
                tk.Label(info_frame, text=door_name, font=("Segoe UI", 10, "bold"),
                        bg="#dbeafe", fg="#1e40af").pack(anchor="w")
                
                details_frame = tk.Frame(info_frame, bg="#dbeafe")
                details_frame.pack(anchor="w")
                
                tk.Label(details_frame, text=f"Zone: {zone_name}", font=SMALL_FONT,
                        bg="#dbeafe", fg="#64748b").pack(side="left", padx=(0, 8))
                tk.Label(details_frame, text=f"📡 Reader: {reader_serial}", font=SMALL_FONT,
                        bg="#dbeafe", fg="#64748b").pack(side="left")
                
                # Catégories
                if categories:
                    categories_frame = tk.Frame(porte_frame, bg="#f9fafb")
                    categories_frame.pack(fill="x", padx=10, pady=(6, 8))
                    
                    total_alarms = sum(len(cat.get('alarms', [])) for cat in categories)
                    tk.Label(categories_frame, text=f"📦 {len(categories)} catégorie(s) - {total_alarms} élément(s) détecté(s)",
                            font=("Segoe UI", 9, "bold"), bg="#f9fafb", anchor="w").pack(anchor="w", pady=(0, 4))
                    
                    # Trier catégories par timestamp
                    categories_with_max_timestamp = []
                    for category in categories:
                        cat_alarms = category.get('alarms', [])
                        max_timestamp = datetime(1970, 1, 1)
                        for alarm in cat_alarms:
                            try:
                                ts_str = alarm.get('timestamp', '1970-01-01 00:00:00')
                                ts = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
                                if ts > max_timestamp:
                                    max_timestamp = ts
                            except:
                                continue
                        categories_with_max_timestamp.append({'category': category, 'max_timestamp': max_timestamp})
                    
                    categories_with_max_timestamp.sort(key=lambda x: x['max_timestamp'], reverse=True)
                    
                    # Afficher catégories
                    for item in categories_with_max_timestamp:
                        category = item['category']
                        cat_name = category.get('category_name', 'Inconnue')
                        cat_icon = category.get('category_icon', '')
                        alarms = category.get('alarms', [])
                        
                        def get_timestamp_for_sort(alarm):
                            try:
                                return datetime.strptime(alarm.get('timestamp', '1970-01-01 00:00:00'), '%Y-%m-%d %H:%M:%S')
                            except:
                                return datetime(1970, 1, 1)
                        
                        alarms_sorted = sorted(alarms, key=get_timestamp_for_sort, reverse=True)
                        
                        cat_row = tk.Frame(categories_frame, bg="#f9fafb")
                        cat_row.pack(fill="x", pady=2)
                        
                        if cat_icon:
                            try:
                                icon_url = get_full_image_url(cat_icon)
                                icon_image = download_and_cache_image(icon_url)
                                if icon_image:
                                    icon_label = tk.Label(cat_row, image=icon_image, bg="#f9fafb")
                                    icon_label.pack(side="left", padx=(0, 5))
                                    icon_label.image = icon_image
                            except:
                                pass
                        
                        tk.Label(cat_row, text=f"• {cat_name} ({len(alarms_sorted)} élément(s))",
                                font=SMALL_FONT, bg="#f9fafb", fg="#374151").pack(side="left", anchor="w")
                        
                        # EPCs
                        epc_frame = tk.Frame(categories_frame, bg="#f9fafb")
                        epc_frame.pack(fill="x", padx=(18, 0), pady=(1, 0))
                        
                        for alarm in alarms_sorted:
                            epc = alarm.get('epc', '—')
                            ts = alarm.get('timestamp', '—')
                            tk.Label(epc_frame, text=f"  └─ {epc} | {ts}", font=MONO_FONT,
                                    bg="#f9fafb", fg=COLORS["muted"], anchor="w").pack(anchor="w", fill="x")
        
        # Séparateur final
        tk.Frame(card, height=1, bg="#e5e7eb").pack(fill="x", padx=16, pady=(8, 0))
        
        # BOUTON avec style moderne
        action_frame = tk.Frame(card, bg="white")
        action_frame.pack(fill="x", padx=16, pady=(10, 14))
        
        btn_text = "✅ Déjà traitée" if alert.get('treated') else "Traiter"
        btn_state = "disabled" if alert.get('treated') else "normal"
        
        # Bouton avec style bleu moderne
        btn = tk.Button(
            action_frame,
            text=btn_text,
            font=("Segoe UI", 10),
            bg="#3b82f6" if btn_state == "normal" else "#9ca3af",
            fg="white",
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2" if btn_state == "normal" else "arrow",
            state=btn_state,
            activebackground="#2563eb" if btn_state == "normal" else "#9ca3af",
            activeforeground="white",
            border=0,
            command=lambda a=alert: self.show_form_for_alert(a)
        )
        btn.pack(side="right")
        
        # Effet hover pour bouton actif
        if btn_state == "normal":
            def on_enter(e):
                btn.configure(bg="#2563eb")
            
            def on_leave(e):
                btn.configure(bg="#3b82f6")
            
            btn.bind("<Enter>", on_enter)
            btn.bind("<Leave>", on_leave)

        logging.debug(f"✅ Widget créé pour règle: {rule_name}")

    def update_alerts_list(self):
        """Met à jour la liste VISUELLE des alertes"""
        try:
            logging.info("🔄 Mise à jour de la liste VISUELLE des alertes")
            
            for widget in self.scrollable_alerts_frame.winfo_children():
                widget.destroy()
            
            with alerts_lock:
                active_alerts = [alert for alert in received_alerts if not alert.get('treated', False)]
                
                if not active_alerts:
                    if self.current_alert_id:
                        current_is_treated = False
                        for alert in received_alerts:
                            if alert.get('id') == self.current_alert_id and alert.get('treated', False):
                                current_is_treated = True
                                break
                        
                        if current_is_treated:
                            self.current_alert_id = None
                            self.form_is_active = False
                            for widget in self.form_container.winfo_children():
                                widget.destroy()
                            
                            ttk.Label(self.form_container, text="✅ Aucune alerte active\nLe système est opérationnel", 
                                    style="Muted.TLabel", justify="center").pack(expand=True)
                    
                    ttk.Label(self.scrollable_alerts_frame, text="✅ Aucune alerte active\nLe système est opérationnel", 
                            foreground=COLORS["success"], font=("Segoe UI", 11), background=COLORS["card"],
                            justify="center").pack(pady=50)
                    logging.info("📭 Aucune alerte active à afficher")
                    return
                
                alerts_to_display = sorted(active_alerts, key=lambda x: x.get('timestamp', ''), reverse=True)
                
                for alert in alerts_to_display:
                    self.create_alert_widget(alert)
                
                # ⭐ La scrollbar se mettra à jour automatiquement
                # grâce au binding <Configure> dans __init__
                
                self.canvas.yview_moveto(0)
                
                # ✅ GESTION DU FORMULAIRE
                if alerts_to_display and not self.form_is_active:
                    # CAS 1: Aucun formulaire actif → afficher le premier
                    if self.current_alert_id:
                        alert_still_exists = any(a.get('id') == self.current_alert_id for a in alerts_to_display)
                        if not alert_still_exists:
                            self.current_alert_id = alerts_to_display[0]['id']
                            self.show_form_in_panel(alerts_to_display[0])
                    else:
                        self.current_alert_id = alerts_to_display[0]['id']
                        self.show_form_in_panel(alerts_to_display[0])
                
                elif self.form_is_active:
                    # CAS 2: Un formulaire est actif
                    if self.current_alert_id:
                        # Chercher l'alerte correspondante dans les nouvelles données
                        current_alert = next(
                            (a for a in alerts_to_display if a.get('id') == self.current_alert_id),
                            None
                        )
                        
                        if current_alert:
                            # ✅ NOUVEAU: Mettre à jour le formulaire avec les nouvelles données MQTT
                            logging.info(f"🔄 Mise à jour du formulaire pour l'alerte {self.current_alert_id}")
                            self.update_form_with_new_data(current_alert)
                        else:
                            # L'alerte n'existe plus → la fermer
                            logging.warning(f"⚠️ Alerte {self.current_alert_id} n'existe plus")
                            self.form_is_active = False
                            self.current_alert_id = None
                            for widget in self.form_container.winfo_children():
                                widget.destroy()
                            
                            ttk.Label(self.form_container, 
                                    text="⚠️ L'alerte a été traitée par un autre utilisateur\nSélectionnez une autre alerte", 
                                    foreground="orange", font=("Arial", 11)).pack(pady=100)
                
                logging.info(f"✅ {len(alerts_to_display)} alertes ACTIVES affichées")
                
        except Exception as e:
            logging.error(f"❌ Erreur mise à jour liste alertes: {e}", exc_info=True)
    
    # =================================================
    # BUSINESS LOGIC - IDENTIQUE AU CODE FONCTIONNEL
    # =================================================
    def update_mqtt_status(self, connected: bool):
        if connected:
            logging.info("🟢 Mise à jour statut MQTT: Connecté")
            self.mqtt_status.set("🟢 Connecté")
            self.status_label.configure(foreground=COLORS["success"])
        else:
            logging.warning("🔴 Mise à jour statut MQTT: Déconnecté")
            self.mqtt_status.set("🔴 Déconnecté")
            self.status_label.configure(foreground=COLORS["danger"])


    def update_form_with_new_data(self, alert):
        """Met à jour UNIQUEMENT les données du formulaire"""
        try:
            logging.info(f"🔄 Mise à jour des données du formulaire pour: {alert.get('id', 'N/A')}")
            
            if self.current_alert_id != alert.get('id'):
                return
            
            saved_description = ""
            saved_status = "traite"
            
            if hasattr(self, 'current_form_widgets'):
                if 'desc_text' in self.current_form_widgets:
                    saved_description = self.current_form_widgets['desc_text'].get("1.0", tk.END).strip()
                if 'status_var' in self.current_form_widgets:
                    saved_status = self.current_form_widgets['status_var'].get()
            
            self.show_form_in_panel(alert, saved_description, saved_status)
            
            logging.info("✅ Formulaire mis à jour avec nouvelles données MQTT")
            
        except Exception as e:
            logging.error(f"❌ Erreur mise à jour formulaire: {e}", exc_info=True)

    def show_form_for_alert(self, alert):
            """Affiche le formulaire pour une alerte spécifique - Version corrigée"""
            logging.info(f"🎯 Affichage formulaire pour alerte ID: {alert.get('id')}")
            
            description_backup = None
            status_backup = None
            
            # PROTECTION: Vérifier que current_form_widgets existe et contient des widgets valides
            if hasattr(self, 'current_form_widgets') and self.current_form_widgets:
                try:
                    # Vérifier si le widget desc_text existe et est valide
                    desc_widget = self.current_form_widgets.get('desc_text')
                    if desc_widget and desc_widget.winfo_exists():
                        description_backup = desc_widget.get("1.0", tk.END).strip()
                    
                    # Vérifier si status_var existe
                    status_widget = self.current_form_widgets.get('status_var')
                    if status_widget:
                        status_backup = status_widget.get()
                except (tk.TclError, AttributeError) as e:
                    # Les widgets ont été détruits, on ignore l'erreur
                    logging.warning(f"⚠️ Widgets détruits, impossible de récupérer les données: {e}")
                    description_backup = None
                    status_backup = None
            
            # Afficher le formulaire avec les données sauvegardées (si disponibles)
            self.show_form_in_panel(alert, description_backup, status_backup)
    def show_form_in_panel(self, alert, description_override=None, status_override=None):
            """Affiche le formulaire - Version complète du code fonctionnel avec style moderne"""
            logging.info(f"📝 Affichage formulaire pour alerte ID: {alert.get('id', 'N/A')}")
            
            self.current_alert_id = alert.get('id')
            self.form_is_active = True
            
            for widget in self.form_container.winfo_children():
                widget.destroy()
            
            # Frame principal SANS scrollbar
            form_frame = tk.Frame(self.form_container, bg=COLORS["card"])
            form_frame.pack(fill="both", expand=True)
            
            # EN-TÊTE
            message_content = alert.get('message', {})
            rule_name = message_content.get('rule_name', 'Règle inconnue')
            
            header_frame = tk.Frame(form_frame, bg="#eff6ff")
            header_frame.pack(fill="x", pady=(0, 16))
            
            tk.Label(header_frame, text=f"🚨 {rule_name}", font=("Segoe UI", 13, "bold"),
                    bg="#eff6ff", fg=COLORS["accent"]).pack(pady=12, padx=16, anchor="w")
            
            # ÉLÉMENTS DÉTECTÉS (logique identique code fonctionnel)
            section_frame = tk.Frame(form_frame, bg=COLORS["card"])
            section_frame.pack(fill="x", padx=16, pady=(0, 12))
            
            ttk.Label(section_frame, text="📦 Éléments détectés", style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            
            all_doors = {}
            if isinstance(message_content, dict):
                if 'doors' in message_content:
                    all_doors = message_content['doors']
                elif 'catagories' in message_content:
                    categories = message_content['catagories']
                    if categories and categories[0].get('alarms'):
                        first_alarm = categories[0]['alarms'][0]
                        door_id = first_alarm.get('door_id', 'N/A')
                        door_name = first_alarm.get('door_name', f'Porte {door_id}')
                        reader_serial = first_alarm.get('reader', 'N/A')
                        zone_name = first_alarm.get('zone_name', 'Zone inconnue')
                        
                        all_doors = {door_id: {
                            'door_info': {'door_id': door_id, 'door_name': door_name, 'reader': reader_serial, 'zone_name': zone_name},
                            'categories': categories
                        }}
            
            all_categories = []
            all_epcs = []
            
            if all_doors:
                for door_key, door_data in all_doors.items():
                    categories = door_data.get('categories', [])
                    for category in categories:
                        cat_id = category.get('category_id')
                        existing_cat = next((c for c in all_categories if c.get('category_id') == cat_id), None)
                        
                        if existing_cat:
                            for new_alarm in category.get('alarms', []):
                                if not any(a.get('epc') == new_alarm.get('epc') for a in existing_cat.get('alarms', [])):
                                    existing_cat.get('alarms', []).append(new_alarm)
                        else:
                            all_categories.append({
                                'category_id': cat_id,
                                'category_name': category.get('category_name'),
                                'category_icon': category.get('category_icon'),
                                'alarms': list(category.get('alarms', []))
                            })
                        
                        for alarm in category.get('alarms', []):
                            epc = alarm.get('epc')
                            if epc and epc not in all_epcs:
                                all_epcs.append(epc)
            
            if all_categories:
                cat_container = tk.Frame(section_frame, bg="#f9fafb", highlightbackground="#e5e7eb", highlightthickness=1)
                cat_container.pack(fill="x", pady=4)
                
                total_elements = sum(len(cat.get('alarms', [])) for cat in all_categories)
                tk.Label(cat_container, text=f"Total: {total_elements} élément(s) dans {len(all_categories)} catégorie(s)",
                        font=SMALL_FONT, bg="#f9fafb", fg=COLORS["muted"]).pack(anchor="w", padx=10, pady=6)
                
                for category in all_categories:
                    cat_name = category.get('category_name', 'Inconnue')
                    alarm_count = len(category.get('alarms', []))
                    
                    cat_row = tk.Frame(cat_container, bg="#f9fafb")
                    cat_row.pack(fill="x", padx=10, pady=3)
                    
                    cat_icon = category.get('category_icon', '')
                    if cat_icon:
                        try:
                            icon_url = get_full_image_url(cat_icon)
                            icon_image = download_and_cache_image(icon_url)
                            if icon_image:
                                icon_label = tk.Label(cat_row, image=icon_image, bg="#f9fafb")
                                icon_label.pack(side="left", padx=(0, 8))
                                icon_label.image = icon_image
                        except:
                            pass
                    
                    tk.Label(cat_row, text=f"• {cat_name}: {alarm_count} élément(s)", 
                            font=BASE_FONT, bg="#f9fafb", fg=COLORS["text"]).pack(side="left")
            else:
                tk.Label(section_frame, text="Aucun élément détecté", font=BASE_FONT, 
                        fg=COLORS["muted"], bg=COLORS["card"]).pack(pady=5, anchor="w")
            
            # DESCRIPTION
            desc_section = tk.Frame(form_frame, bg=COLORS["card"])
            desc_section.pack(fill="x", padx=16, pady=(12, 0))
            
            ttk.Label(desc_section, text="📝 Description", style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            
            toolbar = tk.Frame(desc_section, bg="#f3f4f6")
            toolbar.pack(fill="x", pady=(0, 4))
            
            desc_text = tk.Text(desc_section, height=8, wrap="word", font=BASE_FONT, borderwidth=1, relief="solid", highlightthickness=0)
            desc_text.tag_configure("bold", font=("Segoe UI", 10, "bold"))
            desc_text.tag_configure("italic", font=("Segoe UI", 10, "italic"))
            desc_text.tag_configure("underline", font=("Segoe UI", 10, "underline"))
            
            if description_override:
                desc_text.insert("1.0", description_override)
            
            def on_text_modified(event=None):
                if not self.form_is_active:
                    self.form_is_active = True
            
            desc_text.bind("<KeyPress>", on_text_modified)
            desc_text.bind("<ButtonRelease-1>", on_text_modified)
            
            for btn_text, tag in [("B", "bold"), ("I", "italic"), ("U", "underline")]:
                tk.Button(toolbar, text=btn_text, width=3, bg="#ffffff", fg=COLORS["text"],
                        font=("Segoe UI", 9, "bold"), borderwidth=1, relief="solid",
                        command=lambda t=tag: self.apply_text_tag(desc_text, t)).pack(side=tk.LEFT, padx=2, pady=4)
            
            desc_text.pack(fill="both", expand=True, pady=(0, 8))
            
            # STATUT
            status_section = tk.Frame(form_frame, bg=COLORS["card"])
            status_section.pack(fill="x", padx=16, pady=(12, 0))
            
            ttk.Label(status_section, text="📌 Statut de l'alerte", style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            
            status_var = tk.StringVar(value=status_override if status_override else "traite")
            
            def on_status_changed():
                if not self.form_is_active:
                    self.form_is_active = True
            
            status_frame = tk.Frame(status_section, bg=COLORS["card"])
            status_frame.pack(fill="x", pady=4)
            
            ttk.Radiobutton(status_frame, text="🕒 En cours", variable=status_var, 
                        value="en_cours", command=on_status_changed).pack(side=tk.LEFT, padx=15)
            ttk.Radiobutton(status_frame, text="✅ Traité", variable=status_var, 
                        value="traite", command=on_status_changed).pack(side=tk.LEFT, padx=15)
            
            # BOUTON ENVOYER
            btn_container = tk.Frame(form_frame, bg=COLORS["card"])
            btn_container.pack(fill="x", padx=16, pady=20)
            
            # Créer le bouton
            send_btn = tk.Button(
                btn_container, 
                text="📤 Envoyer le traitement", 
                bg=COLORS["accent"],
                fg="white",
                font=("Segoe UI", 10, "bold"),
                relief="flat",
                bd=0,
                cursor="hand2",
                padx=20,
                pady=10,
                activebackground="#1d4ed8",
                activeforeground="white"
            )
            send_btn.pack(fill="x")
            
            # def envoyer():
            #     alert_id = alert.get('id')
            #     rule_id = alert.get('rule_id')
                
            #     if not status_var.get():
            #         messagebox.showwarning("⚠️ Attention", "Veuillez choisir un statut")
            #         return
                
            #     status = status_var.get()
            #     description = desc_text.get("1.0", tk.END).strip()

            #     if not description:
            #         messagebox.showwarning("⚠️ Attention", "Veuillez remplir la description")
            #         return
                
            #     # DÉSACTIVER LE BOUTON
            #     send_btn.config(
            #         text="⏳ Envoi en cours...",
            #         state="disabled",
            #         bg="#94a3b8",
            #         cursor="wait"
            #     )
            #     desc_text.config(state="disabled")
            #     send_btn.update()
                
            #     # Envoyer la requête
            #     success = send_alert_to_api(rule_id, status, description, all_epcs)
                
            #     if success:
            #         logging.info(f"✅ Alerte {alert_id} traitée avec succès")
                    
            #         # ⭐⭐⭐ RÉCUPÉRER LA LISTE DES READERS
            #         readers_list = alert.get('readers', [])
                    
            #         if not readers_list:
            #             # Fallback : extraction manuelle
            #             readers_list = extract_all_readers_from_alert(alert)
                    
            #         logging.info(f"🎯 Readers concernés: {readers_list}")
                    
            #         # ⭐⭐⭐ ENVOYER RESET À CHAQUE READER
            #         reset_success_count = 0
            #         for reader_serial in readers_list:
            #             if reader_serial and reader_serial != "unknown":
            #                 reset_topic = f"alarm_state_buffer_reset/reader/{reader_serial}"
            #                 reset_payload = {
            #                     "type": "rule",
            #                     "rule_id": rule_id
            #                 }
                            
            #                 try:
            #                     mqtt_listener.publish(reset_topic, reset_payload)
            #                     reset_success_count += 1
            #                     logging.info(f"  📤 Reset envoyé à {reader_serial}")
            #                 except Exception as e:
            #                     logging.error(f"  ❌ Échec reset {reader_serial}: {e}")
                    
            #         if reset_success_count > 0:
            #             logging.info(f"✅ {reset_success_count}/{len(readers_list)} readers réinitialisés")
            #         else:
            #             # Fallback si aucun reader identifié
            #             logging.warning("⚠️ Aucun reader identifié, reset global")
            #             mqtt_listener.publish("alarm_state_buffer_reset", {"ok": True})
                    
            #         # Marquer comme traité LOCALEMENT
            #         with alerts_lock:
            #             global received_alerts
            #             for a in received_alerts:
            #                 if a.get('id') == alert_id:
            #                     a['treated'] = True
            #                     logging.info(f"✅ Alerte {alert_id} marquée comme traitée")
            #                     break
                    
            #         self.form_is_active = False
            #         self.current_alert_id = None
                    
            #         self.update_alerts_list()
                    
            #         # NETTOYER LE FORMULAIRE
            #         for widget in self.form_container.winfo_children():
            #             widget.destroy()
                    
            #         # Afficher message succès
            #         success_frame = tk.Frame(self.form_container, bg=COLORS["card"])
            #         success_frame.pack(fill="both", expand=True)
                    
            #         tk.Label(
            #             success_frame,
            #             text="✅",
            #             font=("Segoe UI", 48),
            #             bg=COLORS["card"],
            #             fg=COLORS["success"]
            #         ).pack(pady=(100, 20))
                    
            #         tk.Label(
            #             success_frame,
            #             text=f"Alerte traitée avec succès !",
            #             font=("Segoe UI", 14, "bold"),
            #             bg=COLORS["card"],
            #             fg=COLORS["text"]
            #         ).pack(pady=(0, 5))
                    
                 
                    
            #         tk.Label(
            #             success_frame,
            #             text="Veuillez sélectionner une autre alerte.",
            #             font=("Segoe UI", 10),
            #             bg=COLORS["card"],
            #             fg=COLORS["muted"]
            #         ).pack()
                    
            #     else:
            #         messagebox.showerror("Erreur", "Échec de l'envoi. Vérifiez votre connexion.")
                    
            #         # RÉACTIVER LE BOUTON
            #         send_btn.config(
            #             text="📤 Envoyer le traitement",
            #             state="normal",
            #             bg=COLORS["accent"],
            #             cursor="hand2"
            #         )
            #         desc_text.config(state="normal")
            def envoyer():
                alert_id = alert.get('id')
                rule_id = alert.get('rule_id')
                
                if not status_var.get():
                    messagebox.showwarning("⚠️ Attention", "Veuillez choisir un statut")
                    return
                
                status = status_var.get()
                description = desc_text.get("1.0", tk.END).strip()

                if not description:
                    messagebox.showwarning("⚠️ Attention", "Veuillez remplir la description")
                    return
                
                # DÉSACTIVER LE BOUTON ET AFFICHER LOADING
                send_btn.config(
                    text="⏳ Envoi en cours...",
                    state="disabled",
                    bg="#94a3b8",  # Gris pour indiquer désactivé
                    cursor="wait"
                )
                desc_text.config(state="disabled")  # Désactiver aussi le champ texte
                
                # Forcer la mise à jour de l'interface
                send_btn.update()
                
                # Envoyer la requête
                success = send_alert_to_api(rule_id, status, description, all_epcs)
                
                if success:
                    logging.info(f"✅ Alerte {alert_id} traitée avec succès")
                    # show_toast("✅ Alerte traitée avec succès", 3000)
                    
                    with alerts_lock:
                        global received_alerts
                        received_alerts = [a for a in received_alerts if a.get('id') != alert_id]
                    
                    self.form_is_active = False
                    self.current_alert_id = None
                    
                    mqtt_listener.publish("alarm_state_buffer_reset", {"ok": True})
                    self.update_alerts_list()
                    
                    # NETTOYER LE FORMULAIRE APRÈS SUCCÈS
                    for widget in self.form_container.winfo_children():
                        widget.destroy()
                    
                    # Afficher un message de confirmation dans le panneau
                    success_frame = tk.Frame(self.form_container, bg=COLORS["card"])
                    success_frame.pack(fill="both", expand=True)
                    
                    tk.Label(
                        success_frame,
                        text="✅",
                        font=("Segoe UI", 48),
                        bg=COLORS["card"],
                        fg=COLORS["success"]
                    ).pack(pady=(100, 20))
                    
                    tk.Label(
                        success_frame,
                        text="Alerte traitée avec succès !",
                        font=("Segoe UI", 14, "bold"),
                        bg=COLORS["card"],
                        fg=COLORS["text"]
                    ).pack(pady=(0, 10))
                    
                    tk.Label(
                        success_frame,
                        text="Veuillez sélectionner une autre alerte.",
                        font=("Segoe UI", 10),
                        bg=COLORS["card"],
                        fg=COLORS["muted"]
                    ).pack()
                    
                else:
                    messagebox.showerror("Erreur", "Échec de l'envoi. Vérifiez votre connexion.")
                    
                    # RÉACTIVER LE BOUTON EN CAS D'ERREUR
                    send_btn.config(
                        text="📤 Envoyer le traitement",
                        state="normal",
                        bg=COLORS["accent"],
                        cursor="hand2"
                    )
                    desc_text.config(state="normal")
            
            send_btn.config(command=envoyer)
            
            # Effets au survol
            def on_enter(e):
                if send_btn['state'] == 'normal':  # Seulement si le bouton est actif
                    send_btn.config(bg="#1d4ed8")

            def on_leave(e):
                if send_btn['state'] == 'normal':  # Seulement si le bouton est actif
                    send_btn.config(bg=COLORS["accent"])

            send_btn.bind("<Enter>", on_enter)
            send_btn.bind("<Leave>", on_leave)
            
            self.current_form_widgets = {'desc_text': desc_text, 'status_var': status_var}
            
            logging.info("✅ Formulaire moderne affiché (sans scrollbar)")
    def apply_text_tag(self, text_widget, tag_name):
        """Applique un tag de formatage"""
        try:
            current_tags = text_widget.tag_names("sel.first")
            if tag_name in current_tags:
                text_widget.tag_remove(tag_name, "sel.first", "sel.last")
            else:
                text_widget.tag_add(tag_name, "sel.first", "sel.last")
        except tk.TclError:
            pass

    def on_close(self):
        """Empêche la fermeture complète"""
        logging.info("🪟 Tentative de fermeture")
        self.root.withdraw()
        logging.info("🟡 Fenêtre masquée")

import tkinter as tk
from tkinter import Toplevel, Label
import threading
import time

def extract_all_readers_from_alert(alert):
    """
    Extrait TOUS les readers depuis une alerte (cas où alert['readers'] est vide).
    Retourne une liste unique de readers.
    """
    readers = set()
    
    try:
        message = alert.get('message', {})
        doors = message.get('doors', {})
        
        for door_key, door_data in doors.items():
            door_info = door_data.get('door_info', {})
            reader = door_info.get('reader')
            if reader and reader != "unknown":
                readers.add(reader)
        
        # Fallback sur categories (ancien format)
        if not readers:
            categories = message.get('catagories', [])
            for category in categories:
                for alarm in category.get('alarms', []):
                    reader = alarm.get('reader')
                    if reader and reader != "unknown":
                        readers.add(reader)
        
        result = list(readers)
        logging.debug(f"📍 Readers extraits: {result}")
        return result
        
    except Exception as e:
        logging.error(f"❌ Erreur extraction readers: {e}", exc_info=True)
        return []
def show_toast(message="Opération réussie", duration=3000):
    """Affiche un toast temporaire avec titre et message"""
    toast = Toplevel()
    toast.overrideredirect(True)
    
    # Position en haut à droite
    toast.geometry("300x50+{}+{}".format(
        toast.winfo_screenwidth() - 320,
        50  # Position Y (haut)
    ))
    
    toast.attributes('-topmost', True)
    toast.configure(bg='#4CAF50')  # Vert succès
    
    # Contenu
 
    Label(toast, text=message, 
          font=("Arial", 11), bg='#4CAF50', fg='white').pack()
    
    toast.after(duration, toast.destroy)

import paho.mqtt.client as mqtt
import threading
import json
import logging

import hashlib
from collections import deque

import socket
import time
import threading
import logging
import paho.mqtt.client as mqtt

import json
import logging
import threading
import time
import random
import socket
import paho.mqtt.client as mqtt
from datetime import datetime

import json
import logging
import threading
import time
import queue
import socket
import random
import pickle
from pathlib import Path
import paho.mqtt.client as mqtt

# Assume notification_queue est défini ailleurs
try:
    from simple_notifier import notification_queue, CONFIG
except:
    notification_queue = queue.Queue()
    CONFIG = {}

class MQTTListener:
    def __init__(self, ui_ref=None):
        logging.info("📡 Initialisation MQTT Listener avec machine tracking")
        self.ui_ref = ui_ref
        
        # Générer les infos de la machine
        self.machine_info = self._get_machine_info()
        
        # Créer client_id avec machine_id
        client_id = self._generate_client_id()
        
        self.client = mqtt.Client(
            client_id=client_id, 
            clean_session=True,
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2
        )
        
        self.client.on_connect = self.on_connect
        self.client.on_disconnect = self.on_disconnect
        self.client.on_message = self.on_message
        
        # Variables de contrôle
        self.last_connect_time = 0
        self.ignore_retain_until = 0
        self.is_running = True
        self.connection_thread = None
        self.reconnect_count = 0
        self.last_heartbeat_check = time.time()
        
        # ✅ NOUVEAU : Gestion robuste des messages
        self.mqtt_db = None
        self.db_ready = threading.Event()  # ✅ Signal quand DB est prête
        self.db_init_thread = None
        self.pending_messages = []
        self.pending_lock = threading.Lock()
        self.pending_file = Path("pending_mqtt_messages.pkl")  # ✅ Persistance sur disque
        self.max_pending = 10000  # ✅ Buffer plus grand
        self.failed_messages = []  # ✅ Messages échoués pour retry
        self.retry_thread = None
        
        # ✅ CHANGEMENT 1 : Charger messages pendants du disque
        self._load_pending_from_disk()
        
        # ✅ CHANGEMENT 2 : Init DB EN PRIORITÉ (synchrone)
       
        threading.Thread(target=self.init_db_sync, daemon=True).start()

        logging.info(f"🖥️  MQTT Listener prêt pour machine: {self.machine_info['hostname']} (ID: {self.machine_info['machine_id']})")
    
    def _load_pending_from_disk(self):
        """✅ Charge les messages non envoyés depuis le disque"""
        try:
            if self.pending_file.exists():
                with open(self.pending_file, 'rb') as f:
                    self.pending_messages = pickle.load(f)
                logging.info(f"📦 {len(self.pending_messages)} messages chargés depuis le disque")
        except Exception as e:
            logging.error(f"❌ Erreur chargement messages: {e}")
            self.pending_messages = []
    
    def _save_pending_to_disk(self):
        """✅ Sauvegarde les messages en attente sur le disque"""
        try:
            with self.pending_lock:
                if self.pending_messages:
                    with open(self.pending_file, 'wb') as f:
                        pickle.dump(self.pending_messages, f)
                    logging.debug(f"💾 {len(self.pending_messages)} messages sauvegardés sur disque")
                elif self.pending_file.exists():
                    self.pending_file.unlink()  # Supprimer si vide
        except Exception as e:
            logging.error(f"❌ Erreur sauvegarde messages: {e}")
    
    def init_db_sync(self):
        """✅ NOUVEAU : Initialise la DB de manière SYNCHRONE (bloquante)"""
        try:
            logging.info("💾 Initialisation DB MySQL (prioritaire)...")
            self.mqtt_db = MQTTDBHandler()
            
            # ✅ Vérifier que la connexion fonctionne
            if self.mqtt_db and self.mqtt_db.pool:
                logging.info("✅ DB MySQL initialisée et connectée")
                self.db_ready.set()  # ✅ Signal que la DB est prête
                
                # ✅ Vider le buffer après init
                self.flush_pending_messages()
                
                # ✅ Démarrer thread retry
                self.start_retry_worker()
            else:
                raise Exception("Pool de connexion non créé")
                
        except Exception as e:
            logging.error(f"❌ CRITIQUE : Échec init DB: {e}")
            self.mqtt_db = None
            # ✅ On continue quand même, les messages seront bufferisés
    
    def start_retry_worker(self):
        """✅ NOUVEAU : Thread qui retente d'envoyer les messages échoués"""
        def retry_worker():
            while self.is_running:
                time.sleep(10)  # Retry toutes les 10 secondes
                
                if not self.mqtt_db or not self.db_ready.is_set():
                    continue
                
                # Réessayer les messages échoués
                with self.pending_lock:
                    if self.failed_messages:
                        logging.info(f"🔄 Retry de {len(self.failed_messages)} messages échoués")
                        
                        retry_list = self.failed_messages.copy()
                        self.failed_messages.clear()
                        
                        for msg_data in retry_list:
                            try:
                                self.mqtt_db.save_message_async(**msg_data)
                            except Exception as e:
                                logging.warning(f"⚠️ Échec retry: {e}")
                                self.failed_messages.append(msg_data)
        
        self.retry_thread = threading.Thread(
            target=retry_worker,
            daemon=True,
            name="MQTT-Retry-Worker"
        )
        self.retry_thread.start()
        logging.info("🔄 Worker retry démarré")
    
    def flush_pending_messages(self):
        """✅ Envoie tous les messages en attente vers la DB"""
        with self.pending_lock:
            if not self.pending_messages:
                logging.debug("📭 Aucun message en attente")
                return
            
            logging.info(f"📤 Envoi de {len(self.pending_messages)} messages en attente vers DB...")
            
            success_count = 0
            fail_count = 0
            
            for msg_data in self.pending_messages:
                try:
                    self.mqtt_db.save_message_async(**msg_data)
                    success_count += 1
                except Exception as e:
                    logging.warning(f"⚠️ Erreur envoi message: {e}")
                    self.failed_messages.append(msg_data)  # ✅ Ajouter aux échecs
                    fail_count += 1
            
            # Vider le buffer
            self.pending_messages.clear()
            self._save_pending_to_disk()  # ✅ Nettoyer le disque
            
            logging.info(f"✅ {success_count} envoyés, {fail_count} échoués")
    
    def _get_machine_info(self):
        """Récupère les informations uniques de la machine"""
        try:
            import platform
            import uuid
            import hashlib
            
            # Nom d'hôte
            hostname = platform.node()
            
            # Adresse MAC
            mac_num = hex(uuid.getnode()).replace('0x', '').upper()
            mac = ':'.join(mac_num[i:i+2] for i in range(0, 11, 2)) if len(mac_num) >= 12 else '00:00:00:00:00:00'
            
            # Adresse IP
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(('8.8.8.8', 80))
                ip = s.getsockname()[0]
                s.close()
            except:
                try:
                    ip = socket.gethostbyname(hostname)
                except:
                    ip = '127.0.0.1'
            
            # Générer un ID unique
            unique_string = f"{hostname}_{mac}_{ip}"
            machine_id = hashlib.md5(unique_string.encode()).hexdigest()[:12]
            
            machine_info = {
                'machine_id': f"PC_{machine_id}",
                'hostname': hostname,
                'ip': ip,
                'mac': mac,
                'system': platform.system(),
                'release': platform.release()
            }
            
            return machine_info
            
        except Exception as e:
            logging.error(f"❌ Erreur récupération infos machine: {e}")
            import uuid
            return {
                'machine_id': f"PC_{uuid.uuid4().hex[:8]}",
                'hostname': 'unknown',
                'ip': '127.0.0.1',
                'mac': '00:00:00:00:00:00',
                'system': 'unknown',
                'release': 'unknown'
            }
    
    def _generate_client_id(self):
        """Génère un client_id unique avec machine_id"""
        timestamp = int(time.time())
        random_suffix = random.randint(1000, 9999)
        machine_short_id = self.machine_info['machine_id'].replace('PC_', '')[:6]
        return f"zonex_{machine_short_id}_{timestamp}_{random_suffix}"
    
    def on_connect(self, client, userdata, flags, reason_code, properties):
        """Callback pour connexion MQTT"""
        current_time = time.time()
        
        if reason_code == 0:
            self.reconnect_count = 0
            self.last_heartbeat_check = current_time  # ✅ Reset heartbeat
            logging.info(f"✅ Connecté au broker MQTT depuis {self.machine_info['hostname']}")
            
            # Gérer reconnexion
            if current_time - self.last_connect_time < 30:
                logging.info("⚠️ Reconnexion rapide - ignore retain 30s")
                self.ignore_retain_until = current_time + 30
            
            self.last_connect_time = current_time
            
            # ✅ Mettre à jour UI dans le thread Tkinter
            if self.ui_ref:
                try:
                    self.ui_ref.root.after(0, lambda: self.ui_ref.update_mqtt_status(True))
                except Exception as e:
                    logging.warning(f"⚠️ Erreur MAJ UI: {e}")
            
            # S'abonner avec vérification
            try:
                if 'mqtt_topic' in CONFIG:
                    topic = CONFIG['mqtt_topic']
                    result, mid = client.subscribe(topic, qos=1)
                    if result == mqtt.MQTT_ERR_SUCCESS:
                        logging.info(f"✅ Souscrit: {topic} (QoS 1)")
                    else:
                        logging.error(f"❌ Échec souscription: {result}")
                else:
                    result, mid = client.subscribe("alert_grouped/#", qos=1)
                    if result == mqtt.MQTT_ERR_SUCCESS:
                        logging.info(f"✅ Souscrit au topic par défaut: alert_grouped/# (QoS 1)")
                    else:
                        logging.error(f"❌ Échec souscription au topic par défaut: {result}")
                        
            except Exception as e:
                logging.error(f"❌ Erreur lors de la souscription: {e}")
        else:
            self.reconnect_count += 1
            logging.error(f"❌ Erreur connexion MQTT: {reason_code} (reconnexion #{self.reconnect_count})")
            if self.ui_ref:
                try:
                    self.ui_ref.root.after(0, lambda: self.ui_ref.update_mqtt_status(False))
                except:
                    pass
    
    def on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties):
        """Callback pour déconnexion MQTT"""
        logging.warning(f"⚠️ Déconnecté du broker MQTT depuis {self.machine_info['hostname']} - Raison: {reason_code}")
        self.last_connect_time = time.time()
        
        # ✅ Mettre à jour UI immédiatement
        if self.ui_ref:
            try:
                self.ui_ref.root.after(0, lambda: self.ui_ref.update_mqtt_status(False))
            except:
                pass
        
        # Afficher message explicite selon le code d'erreur
        if reason_code == 7:
            logging.warning("🌐 Perte de connexion réseau détectée")
        elif reason_code != 0:
            logging.warning(f"🔌 Déconnexion inattendue (code: {reason_code})")
    
    def on_message(self, client, userdata, msg):
        """Callback pour message MQTT"""
        try:
            current_time = time.time()
            self.last_heartbeat_check = current_time
            
            if msg.retain and current_time < self.ignore_retain_until:
                logging.info(f"⏸️ Message retain ignoré: {msg.topic}")
                return
            
            payload = msg.payload.decode('utf-8')
            mqtt_topic = msg.topic
            
            logging.info(f"📩 Message reçu sur {mqtt_topic}")
            
            try:
                data = json.loads(payload)
                x = str(data[0].get('catagories')[0].get('alarms')[0].get('company'))
                company_from_config = str(CONFIG['company_id'])
                result = x == company_from_config
                logging.info(f" on message /  company list {x} / company app {CONFIG['company_id']} / {result}")
                if result:                
                    # Préparer les données du message
                    client_id_value = self._get_client_id()
                    
                    msg_data = {
                        'topic': mqtt_topic,
                        'payload': data,
                        'qos': msg.qos,
                        'retain': msg.retain,
                        'client_id': client_id_value,
                        'machine_info': self.machine_info
                    }
                    
                    # ✅ AMÉLIORATION : Gestion robuste de la sauvegarde
                    if self.db_ready.is_set() and self.mqtt_db:
                        # DB prête : sauvegarder directement
                        try:
                            self.mqtt_db.save_message_async(**msg_data)
                            logging.debug("✅ Message envoyé à DB")
                        except Exception as e:
                            logging.warning(f"⚠️ Échec sauvegarde DB, ajout au buffer retry: {e}")
                            with self.pending_lock:
                                self.failed_messages.append(msg_data)  # ✅ Retry plus tard
                    else:
                        # DB pas prête : buffer + disque
                        with self.pending_lock:
                            if len(self.pending_messages) < self.max_pending:
                                self.pending_messages.append(msg_data)
                                logging.debug(f"📦 Message bufferisé ({len(self.pending_messages)}/{self.max_pending})")
                                
                                # ✅ Sauvegarder périodiquement sur disque
                                if len(self.pending_messages) % 100 == 0:
                                    self._save_pending_to_disk()
                            else:
                                logging.error(f"🔴 CRITIQUE : Buffer plein ({self.max_pending}), message PERDU !")
                                # ✅ Forcer sauvegarde disque même si buffer plein
                                self._save_pending_to_disk()
                    
                    # ✅ Toujours traiter le message pour notification
                    notification_queue.put((data, mqtt_topic))
                
            except json.JSONDecodeError as e:
                logging.error(f"❌ Erreur parsing JSON: {e}")
                
        except Exception as e:
            logging.error(f"❌ Erreur traitement message: {e}", exc_info=True)
    
    def _get_client_id(self):
        """✅ Récupère le client_id de manière sûre"""
        try:
            if hasattr(self.client, '_client_id'):
                if isinstance(self.client._client_id, bytes):
                    return self.client._client_id.decode('utf-8')
                else:
                    return str(self.client._client_id)
        except:
            pass
        return self._generate_client_id()
    
    def check_network_availability(self):
        """Vérifie si Internet est disponible"""
        try:
            socket.setdefaulttimeout(3)
            socket.gethostbyname('www.google.com')
            return True
        except:
            return False
        finally:
            socket.setdefaulttimeout(None)
    
    def wait_for_network(self, max_wait=60):
        """Attend que le réseau soit disponible"""
        logging.info("🔍 Attente disponibilité réseau...")
        start_time = time.time()
        
        while time.time() - start_time < max_wait and self.is_running:
            if self.check_network_availability():
                logging.info("✅ Réseau disponible")
                return True
            
            logging.debug("⏳ Réseau non disponible, attente 3s...")
            time.sleep(3)
        
        logging.warning("⏰ Timeout attente réseau")
        return False
    
    def start_heartbeat_monitor(self):
        """✅ Moniteur actif - détecte ET force la reconnexion"""
        def monitor():
            logging.info("💓 Démarrage moniteur heartbeat")
            
            while self.is_running:
                time.sleep(2)  # Vérifier toutes les 2 secondes
                
                current_time = time.time()
                time_since_last = current_time - self.last_heartbeat_check
                
                # ✅ Si pas de signe de vie depuis 8s
                if time_since_last > 8:
                    
                    # ✅ Vérifier vraiment l'état de la connexion
                    if not self.client.is_connected():
                        logging.warning(f"⚠️ Déconnexion détectée ({time_since_last:.0f}s sans activité)")
                        
                        # ✅ Mettre à jour UI
                        if self.ui_ref:
                            try:
                                self.ui_ref.root.after(0, lambda: self.ui_ref.update_mqtt_status(False))
                            except:
                                pass
                        
                        # ✅✅✅ FORCER LA RECONNEXION
                        try:
                            logging.info("🔄 Force reconnexion...")
                            self.client.reconnect()
                            self.last_heartbeat_check = current_time
                        except Exception as e:
                            logging.debug(f"⚠️ Reconnexion impossible: {e}")
                    else:
                        # Connecté mais pas de message → reset timer
                        self.last_heartbeat_check = current_time
        
        threading.Thread(target=monitor, daemon=True, name="MQTT-Heartbeat").start()
    
    def connect_with_retry(self):
        """Connexion avec reconnexion automatique"""
        
        # ✅ Configuration reconnexion automatique RAPIDE
        self.client.reconnect_delay_set(min_delay=1, max_delay=30)
        
        while self.is_running:
            try:
                # Vérifier réseau
                if not self.check_network_availability():
                    logging.info("⏳ Pas de réseau, attente...")
                    if not self.wait_for_network(max_wait=60):
                        time.sleep(3)
                        continue
                
                logging.info(f"🔗 Connexion MQTT depuis {self.machine_info['hostname']}...")
                
                try:
                    # ✅ Keepalive 15s (compromis entre 5 et 30)
                    self.client.connect(
                        CONFIG.get('mqtt_broker', 'localhost'),
                        CONFIG.get('mqtt_port', 1883),
                        keepalive=15
                    )
                except Exception as e:
                    logging.error(f"❌ Échec connexion: {e}")
                    time.sleep(3)
                    continue
                
                logging.info("✅ Lancement boucle MQTT...")
                
                # ✅ Boucle avec reconnexion automatique
                self.client.loop_forever(retry_first_connection=True)
                
                if not self.is_running:
                    break
                    
                logging.warning("⚠️ Boucle MQTT terminée, redémarrage...")
                time.sleep(2)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logging.error(f"❌ Erreur: {e}")
                time.sleep(3)
    
    def start(self):
        """Démarre le listener MQTT"""
        if self.connection_thread and self.connection_thread.is_alive():
            logging.warning("⚠️ MQTT Listener déjà démarré")
            return
        
        self.is_running = True
        
        # ✅ DB déjà initialisée dans __init__, on démarre juste MQTT
        self.connection_thread = threading.Thread(
            target=self.connect_with_retry,
            daemon=True,
            name=f"MQTT-Thread-{self.machine_info['hostname']}"
        )
        self.connection_thread.start()
        
        # Démarrer heartbeat
        self.start_heartbeat_monitor()
        
        logging.info(f"✅ MQTT Listener démarré sur {self.machine_info['hostname']}")
    
    def stop(self):
        """Arrête proprement le listener"""
        logging.info(f"🛑 Arrêt du MQTT Listener...")
        self.is_running = False
        
        # ✅ Sauvegarder les messages en attente
        self._save_pending_to_disk()
        
        if self.mqtt_db:
            self.mqtt_db.stop()
        
        try:
            self.client.disconnect()
            self.client.loop_stop()
        except:
            pass
        
        if self.connection_thread:
            self.connection_thread.join(timeout=5)
        
        logging.info("✅ MQTT Listener arrêté")
    
    def publish(self, topic, payload, qos=1, retain=False):
        """Publie un message MQTT"""
        try:
            if isinstance(payload, dict):
                payload = json.dumps(payload)
            
            result = self.client.publish(topic, payload, qos=qos, retain=retain)
            
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                logging.info(f"✅ Publié sur {topic} (QoS {qos})")
                return True
            else:
                logging.error(f"❌ Erreur publication: {result.rc}")
                return False
        except Exception as e:
            logging.error(f"❌ Exception publication: {e}")
            return False
    
    def get_status(self):
        """Retourne le statut du listener"""
        with self.pending_lock:
            pending_count = len(self.pending_messages)
            failed_count = len(self.failed_messages)
        
        db_connected = False
        if self.mqtt_db and hasattr(self.mqtt_db, 'pool'):
            db_connected = self.mqtt_db.pool is not None
        
        return {
            'machine_id': self.machine_info['machine_id'],
            'hostname': self.machine_info['hostname'],
            'ip': self.machine_info['ip'],
            'is_running': self.is_running,
            'connected': self.client.is_connected(),
            'reconnect_count': self.reconnect_count,
            'last_connect': self.last_connect_time,
            'db_connected': db_connected,
            'db_ready': self.db_ready.is_set(),  # ✅ NOUVEAU
            'pending_messages': pending_count,
            'failed_messages': failed_count     # ✅ NOUVEAU
        } 
# class MQTTListener:
#     def __init__(self, ui_ref=None):
#         logging.info("📡 Initialisation MQTT Listener avec machine tracking")
#         self.ui_ref = ui_ref
        
#         # Générer les infos de la machine
#         self.machine_info = self._get_machine_info()
        
#         # Créer client_id avec machine_id
#         client_id = self._generate_client_id()
        
#         self.client = mqtt.Client(
#             client_id=client_id, 
#             clean_session=True,
#             callback_api_version=mqtt.CallbackAPIVersion.VERSION2
#         )
        
#         self.client.on_connect = self.on_connect
#         self.client.on_disconnect = self.on_disconnect
#         self.client.on_message = self.on_message
        
#         # Variables de contrôle
#         self.last_connect_time = 0
#         self.ignore_retain_until = 0
#         self.is_running = True
#         self.connection_thread = None
#         self.reconnect_count = 0
#         self.last_heartbeat_check = time.time()
        
#         # ✅ NOUVEAU : Gestion robuste des messages
#         self.mqtt_db = None
#         self.db_ready = threading.Event()  # ✅ Signal quand DB est prête
#         self.db_init_thread = None
#         self.pending_messages = []
#         self.pending_lock = threading.Lock()
#         self.pending_file = Path("pending_mqtt_messages.pkl")  # ✅ Persistance sur disque
#         self.max_pending = 10000  # ✅ Buffer plus grand
#         self.failed_messages = []  # ✅ Messages échoués pour retry
#         self.retry_thread = None
        
#         self.recent_messages = []
#         self.recent_lock = threading.Lock()
#         self.max_recent = 100
#         # ✅ CHANGEMENT 1 : Charger messages pendants du disque
#         self._load_pending_from_disk()
        
#         # ✅ CHANGEMENT 2 : Init DB EN PRIORITÉ (synchrone)
       
#         threading.Thread(target=self.init_db_sync, daemon=True).start()

#         logging.info(f"🖥️  MQTT Listener prêt pour machine: {self.machine_info['hostname']} (ID: {self.machine_info['machine_id']})")
#     def _get_message_hash(self, topic, payload):
#         """Hash unique pour détecter les doublons"""
#         import hashlib
#         content = f"{topic}:{payload}:{int(time.time() / 5)}"
#         return hashlib.md5(content.encode()).hexdigest()[:16]

#     def _is_duplicate(self, topic, payload):
#         """Vérifie si message déjà vu"""
#         msg_hash = self._get_message_hash(topic, payload)
#         with self.recent_lock:
#             if msg_hash in self.recent_messages:
#                 return True
#             self.recent_messages.append(msg_hash)
#             if len(self.recent_messages) > self.max_recent:
#                 self.recent_messages.pop(0)
#             return False
#     def _load_pending_from_disk(self):
#         """✅ Charge les messages non envoyés depuis le disque"""
#         try:
#             if self.pending_file.exists():
#                 with open(self.pending_file, 'rb') as f:
#                     self.pending_messages = pickle.load(f)
#                 logging.info(f"📦 {len(self.pending_messages)} messages chargés depuis le disque")
#         except Exception as e:
#             logging.error(f"❌ Erreur chargement messages: {e}")
#             self.pending_messages = []
    
#     def _save_pending_to_disk(self):
#         """✅ Sauvegarde les messages en attente sur le disque"""
#         try:
#             with self.pending_lock:
#                 if self.pending_messages:
#                     with open(self.pending_file, 'wb') as f:
#                         pickle.dump(self.pending_messages, f)
#                     logging.debug(f"💾 {len(self.pending_messages)} messages sauvegardés sur disque")
#                 elif self.pending_file.exists():
#                     self.pending_file.unlink()  # Supprimer si vide
#         except Exception as e:
#             logging.error(f"❌ Erreur sauvegarde messages: {e}")
    
#     def init_db_sync(self):
#         """✅ NOUVEAU : Initialise la DB de manière SYNCHRONE (bloquante)"""
#         try:
#             logging.info("💾 Initialisation DB MySQL (prioritaire)...")
#             self.mqtt_db = MQTTDBHandler()
            
#             # ✅ Vérifier que la connexion fonctionne
#             if self.mqtt_db and self.mqtt_db.pool:
#                 logging.info("✅ DB MySQL initialisée et connectée")
#                 self.db_ready.set()  # ✅ Signal que la DB est prête
                
#                 # ✅ Vider le buffer après init
#                 self.flush_pending_messages()
                
#                 # ✅ Démarrer thread retry
#                 self.start_retry_worker()
#             else:
#                 raise Exception("Pool de connexion non créé")
                
#         except Exception as e:
#             logging.error(f"❌ CRITIQUE : Échec init DB: {e}")
#             self.mqtt_db = None
#             # ✅ On continue quand même, les messages seront bufferisés
    
#     def start_retry_worker(self):
#         """✅ NOUVEAU : Thread qui retente d'envoyer les messages échoués"""
#         def retry_worker():
#             while self.is_running:
#                 time.sleep(10)  # Retry toutes les 10 secondes
                
#                 if not self.mqtt_db or not self.db_ready.is_set():
#                     continue
                
#                 # Réessayer les messages échoués
#                 with self.pending_lock:
#                     if self.failed_messages:
#                         logging.info(f"🔄 Retry de {len(self.failed_messages)} messages échoués")
                        
#                         retry_list = self.failed_messages.copy()
#                         self.failed_messages.clear()
                        
#                         for msg_data in retry_list:
#                             try:
#                                 self.mqtt_db.save_message_async(**msg_data)
#                             except Exception as e:
#                                 logging.warning(f"⚠️ Échec retry: {e}")
#                                 self.failed_messages.append(msg_data)
        
#         self.retry_thread = threading.Thread(
#             target=retry_worker,
#             daemon=True,
#             name="MQTT-Retry-Worker"
#         )
#         self.retry_thread.start()
#         logging.info("🔄 Worker retry démarré")
    
#     def flush_pending_messages(self):
#         """✅ Envoie tous les messages en attente vers la DB"""
#         with self.pending_lock:
#             if not self.pending_messages:
#                 logging.debug("📭 Aucun message en attente")
#                 return
            
#             logging.info(f"📤 Envoi de {len(self.pending_messages)} messages en attente vers DB...")
            
#             success_count = 0
#             fail_count = 0
            
#             for msg_data in self.pending_messages:
#                 try:
#                     self.mqtt_db.save_message_async(**msg_data)
#                     success_count += 1
#                 except Exception as e:
#                     logging.warning(f"⚠️ Erreur envoi message: {e}")
#                     self.failed_messages.append(msg_data)  # ✅ Ajouter aux échecs
#                     fail_count += 1
            
#             # Vider le buffer
#             self.pending_messages.clear()
#             self._save_pending_to_disk()  # ✅ Nettoyer le disque
            
#             logging.info(f"✅ {success_count} envoyés, {fail_count} échoués")
    
#     def _get_machine_info(self):
#         """Récupère les informations uniques de la machine"""
#         try:
#             import platform
#             import uuid
#             import hashlib
            
#             # Nom d'hôte
#             hostname = platform.node()
            
#             # Adresse MAC
#             mac_num = hex(uuid.getnode()).replace('0x', '').upper()
#             mac = ':'.join(mac_num[i:i+2] for i in range(0, 11, 2)) if len(mac_num) >= 12 else '00:00:00:00:00:00'
            
#             # Adresse IP
#             try:
#                 s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#                 s.connect(('8.8.8.8', 80))
#                 ip = s.getsockname()[0]
#                 s.close()
#             except:
#                 try:
#                     ip = socket.gethostbyname(hostname)
#                 except:
#                     ip = '127.0.0.1'
            
#             # Générer un ID unique
#             unique_string = f"{hostname}_{mac}_{ip}"
#             machine_id = hashlib.md5(unique_string.encode()).hexdigest()[:12]
            
#             machine_info = {
#                 'machine_id': f"PC_{machine_id}",
#                 'hostname': hostname,
#                 'ip': ip,
#                 'mac': mac,
#                 'system': platform.system(),
#                 'release': platform.release()
#             }
            
#             return machine_info
            
#         except Exception as e:
#             logging.error(f"❌ Erreur récupération infos machine: {e}")
#             import uuid
#             return {
#                 'machine_id': f"PC_{uuid.uuid4().hex[:8]}",
#                 'hostname': 'unknown',
#                 'ip': '127.0.0.1',
#                 'mac': '00:00:00:00:00:00',
#                 'system': 'unknown',
#                 'release': 'unknown'
#             }
    
#     def _generate_client_id(self):
#         """Génère un client_id unique avec machine_id"""
#         timestamp = int(time.time())
#         random_suffix = random.randint(1000, 9999)
#         machine_short_id = self.machine_info['machine_id'].replace('PC_', '')[:6]
#         return f"zonex_{machine_short_id}_{timestamp}_{random_suffix}"
    
#     def on_connect(self, client, userdata, flags, reason_code, properties):
#         """Callback pour connexion MQTT"""
#         current_time = time.time()
        
#         if reason_code == 0:
#             self.reconnect_count = 0
#             self.last_heartbeat_check = current_time  # ✅ Reset heartbeat
#             logging.info(f"✅ Connecté au broker MQTT depuis {self.machine_info['hostname']}")
            
#             # Gérer reconnexion
#             if current_time - self.last_connect_time < 60:
#                 logging.info("⚠️ Reconnexion rapide - ignore retain 60s")
#                 self.ignore_retain_until = current_time + 60
            
#             self.last_connect_time = current_time
            
#             # ✅ Mettre à jour UI dans le thread Tkinter
#             if self.ui_ref:
#                 try:
#                     self.ui_ref.root.after(0, lambda: self.ui_ref.update_mqtt_status(True))
#                 except Exception as e:
#                     logging.warning(f"⚠️ Erreur MAJ UI: {e}")
            
#             # S'abonner avec vérification
#             try:
#                 if 'mqtt_topic' in CONFIG:
#                     topic = CONFIG['mqtt_topic']
#                     result, mid = client.subscribe(topic, qos=1)
#                     if result == mqtt.MQTT_ERR_SUCCESS:
#                         logging.info(f"✅ Souscrit: {topic} (QoS 1)")
#                     else:
#                         logging.error(f"❌ Échec souscription: {result}")
#                 else:
#                     result, mid = client.subscribe("alert_grouped/#", qos=1)
#                     if result == mqtt.MQTT_ERR_SUCCESS:
#                         logging.info(f"✅ Souscrit au topic par défaut: alert_grouped/# (QoS 1)")
#                     else:
#                         logging.error(f"❌ Échec souscription au topic par défaut: {result}")
                        
#             except Exception as e:
#                 logging.error(f"❌ Erreur lors de la souscription: {e}")
#         else:
#             self.reconnect_count += 1
#             logging.error(f"❌ Erreur connexion MQTT: {reason_code} (reconnexion #{self.reconnect_count})")
#             if self.ui_ref:
#                 try:
#                     self.ui_ref.root.after(0, lambda: self.ui_ref.update_mqtt_status(False))
#                 except:
#                     pass
    
#     def on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties):
#         """Callback pour déconnexion MQTT"""
#         logging.warning(f"⚠️ Déconnecté du broker MQTT depuis {self.machine_info['hostname']} - Raison: {reason_code}")
#         self.last_connect_time = time.time()
        
#         # ✅ Mettre à jour UI immédiatement
#         if self.ui_ref:
#             try:
#                 self.ui_ref.root.after(0, lambda: self.ui_ref.update_mqtt_status(False))
#             except:
#                 pass
        
#         # Afficher message explicite selon le code d'erreur
#         if reason_code == 7:
#             logging.warning("🌐 Perte de connexion réseau détectée")
#         elif reason_code != 0:
#             logging.warning(f"🔌 Déconnexion inattendue (code: {reason_code})")
    
#     def on_message(self, client, userdata, msg):
#         """Callback pour message MQTT"""
#         try:
#             current_time = time.time()
#             self.last_heartbeat_check = current_time
            
#             payload = msg.payload.decode('utf-8')
#             mqtt_topic = msg.topic
            
#             # ✅ 1. Vérifier doublon en PREMIER (avant tout traitement)
#             if self._is_duplicate(mqtt_topic, payload):
#                 logging.debug(f"♻️ Doublon ignoré: {mqtt_topic}")
#                 return
            
#             # ✅ 2. Log détaillé pour debug
#             logging.info(f"📩 {mqtt_topic} | retain={msg.retain} | qos={msg.qos}")
            
#             # ✅ 3. Ignorer les messages retain pendant la fenêtre de reconnexion (60s)
#             if msg.retain and current_time < self.ignore_retain_until:
#                 remaining = int(self.ignore_retain_until - current_time)
#                 logging.info(f"⏸️ RETAIN ignoré ({remaining}s restantes): {mqtt_topic}")
#                 return
            
#             # ✅ 4. Traiter le message
#             try:
#                 data = json.loads(payload)
#                 x = str(data[0].get('catagories')[0].get('alarms')[0].get('company'))
#                 company_from_config = str(CONFIG['company_id'])
#                 result = x == company_from_config
                
#                 logging.info(f"Company match: {x} vs {CONFIG['company_id']} = {result}")
                
#                 if not result:
#                     return  # Pas le bon company_id, ignorer silencieusement
                
#                 # Préparer les données
#                 client_id_value = self._get_client_id()
                
#                 msg_data = {
#                     'topic': mqtt_topic,
#                     'payload': data,
#                     'qos': msg.qos,
#                     'retain': msg.retain,
#                     'client_id': client_id_value,
#                     'machine_info': self.machine_info,
#                     'timestamp': current_time  # ✅ Ajouter timestamp pour traçabilité
#                 }
                
#                 # Sauvegarde DB ou buffer
#                 if self.db_ready.is_set() and self.mqtt_db:
#                     try:
#                         self.mqtt_db.save_message_async(**msg_data)
#                         logging.debug("✅ Message envoyé à DB")
#                     except Exception as e:
#                         logging.warning(f"⚠️ Échec DB, ajout au retry: {e}")
#                         with self.pending_lock:
#                             self.failed_messages.append(msg_data)
#                 else:
#                     # Buffer si DB pas prête
#                     with self.pending_lock:
#                         if len(self.pending_messages) < self.max_pending:
#                             self.pending_messages.append(msg_data)
#                             logging.debug(f"📦 Bufferisé ({len(self.pending_messages)}/{self.max_pending})")
                            
#                             if len(self.pending_messages) % 100 == 0:
#                                 self._save_pending_to_disk()
#                         else:
#                             logging.error(f"🔴 Buffer plein, message PERDU !")
#                             self._save_pending_to_disk()
                
#                 # Notification
#                 notification_queue.put((data, mqtt_topic))
                
#             except json.JSONDecodeError as e:
#                 logging.error(f"❌ JSON invalide: {e}")
                
#         except Exception as e:
#             logging.error(f"❌ Erreur traitement message: {e}", exc_info=True)
#     def _get_client_id(self):
#         """✅ Récupère le client_id de manière sûre"""
#         try:
#             if hasattr(self.client, '_client_id'):
#                 if isinstance(self.client._client_id, bytes):
#                     return self.client._client_id.decode('utf-8')
#                 else:
#                     return str(self.client._client_id)
#         except:
#             pass
#         return self._generate_client_id()
    
#     def check_network_availability(self):
#         """Vérifie si Internet est disponible"""
#         try:
#             socket.setdefaulttimeout(3)
#             socket.gethostbyname('www.google.com')
#             return True
#         except:
#             return False
#         finally:
#             socket.setdefaulttimeout(None)
    
#     def wait_for_network(self, max_wait=60):
#         """Attend que le réseau soit disponible"""
#         logging.info("🔍 Attente disponibilité réseau...")
#         start_time = time.time()
        
#         while time.time() - start_time < max_wait and self.is_running:
#             if self.check_network_availability():
#                 logging.info("✅ Réseau disponible")
#                 return True
            
#             logging.debug("⏳ Réseau non disponible, attente 3s...")
#             time.sleep(3)
        
#         logging.warning("⏰ Timeout attente réseau")
#         return False
    
#     def start_heartbeat_monitor(self):
#         """✅ Moniteur actif - détecte ET force la reconnexion"""
#         def monitor():
#             logging.info("💓 Démarrage moniteur heartbeat")
            
#             while self.is_running:
#                 time.sleep(2)  # Vérifier toutes les 2 secondes
                
#                 current_time = time.time()
#                 time_since_last = current_time - self.last_heartbeat_check
                
#                 # ✅ Si pas de signe de vie depuis 8s
#                 if time_since_last > 8:
                    
#                     # ✅ Vérifier vraiment l'état de la connexion
#                     if not self.client.is_connected():
#                         logging.warning(f"⚠️ Déconnexion détectée ({time_since_last:.0f}s sans activité)")
                        
#                         # ✅ Mettre à jour UI
#                         if self.ui_ref:
#                             try:
#                                 self.ui_ref.root.after(0, lambda: self.ui_ref.update_mqtt_status(False))
#                             except:
#                                 pass
                        
#                         # ✅✅✅ FORCER LA RECONNEXION
#                         try:
#                             logging.info("🔄 Force reconnexion...")
#                             self.client.reconnect()
#                             self.last_heartbeat_check = current_time
#                         except Exception as e:
#                             logging.debug(f"⚠️ Reconnexion impossible: {e}")
#                     else:
#                         # Connecté mais pas de message → reset timer
#                         self.last_heartbeat_check = current_time
        
#         threading.Thread(target=monitor, daemon=True, name="MQTT-Heartbeat").start()
    
#     def connect_with_retry(self):
#         """Connexion avec reconnexion automatique"""
        
#         # ✅ Configuration reconnexion automatique RAPIDE
#         self.client.reconnect_delay_set(min_delay=1, max_delay=30)
        
#         while self.is_running:
#             try:
#                 # Vérifier réseau
#                 if not self.check_network_availability():
#                     logging.info("⏳ Pas de réseau, attente...")
#                     if not self.wait_for_network(max_wait=60):
#                         time.sleep(3)
#                         continue
                
#                 logging.info(f"🔗 Connexion MQTT depuis {self.machine_info['hostname']}...")
                
#                 try:
#                     # ✅ Keepalive 15s (compromis entre 5 et 30)
#                     self.client.connect(
#                         CONFIG.get('mqtt_broker', 'localhost'),
#                         CONFIG.get('mqtt_port', 1883),
#                         keepalive=15
#                     )
#                 except Exception as e:
#                     logging.error(f"❌ Échec connexion: {e}")
#                     time.sleep(3)
#                     continue
                
#                 logging.info("✅ Lancement boucle MQTT...")
                
#                 # ✅ Boucle avec reconnexion automatique
#                 self.client.loop_forever(retry_first_connection=True)
                
#                 if not self.is_running:
#                     break
                    
#                 logging.warning("⚠️ Boucle MQTT terminée, redémarrage...")
#                 time.sleep(2)
                
#             except KeyboardInterrupt:
#                 break
#             except Exception as e:
#                 logging.error(f"❌ Erreur: {e}")
#                 time.sleep(3)
    
#     def start(self):
#         """Démarre le listener MQTT"""
#         if self.connection_thread and self.connection_thread.is_alive():
#             logging.warning("⚠️ MQTT Listener déjà démarré")
#             return
        
#         self.is_running = True
        
#         # ✅ DB déjà initialisée dans __init__, on démarre juste MQTT
#         self.connection_thread = threading.Thread(
#             target=self.connect_with_retry,
#             daemon=True,
#             name=f"MQTT-Thread-{self.machine_info['hostname']}"
#         )
#         self.connection_thread.start()
        
#         # Démarrer heartbeat
#         self.start_heartbeat_monitor()
        
#         logging.info(f"✅ MQTT Listener démarré sur {self.machine_info['hostname']}")
    
#     def stop(self):
#         """Arrête proprement le listener"""
#         logging.info(f"🛑 Arrêt du MQTT Listener...")
#         self.is_running = False
        
#         # ✅ Sauvegarder les messages en attente
#         self._save_pending_to_disk()
        
#         if self.mqtt_db:
#             self.mqtt_db.stop()
        
#         try:
#             self.client.disconnect()
#             self.client.loop_stop()
#         except:
#             pass
        
#         if self.connection_thread:
#             self.connection_thread.join(timeout=5)
        
#         logging.info("✅ MQTT Listener arrêté")
    
#     def publish(self, topic, payload, qos=1, retain=False):
#         """Publie un message MQTT"""
#         try:
#             if isinstance(payload, dict):
#                 payload = json.dumps(payload)
            
#             result = self.client.publish(topic, payload, qos=qos, retain=retain)
            
#             if result.rc == mqtt.MQTT_ERR_SUCCESS:
#                 logging.info(f"✅ Publié sur {topic} (QoS {qos})")
#                 return True
#             else:
#                 logging.error(f"❌ Erreur publication: {result.rc}")
#                 return False
#         except Exception as e:
#             logging.error(f"❌ Exception publication: {e}")
#             return False
    
#     def get_status(self):
#         """Retourne le statut du listener"""
#         with self.pending_lock:
#             pending_count = len(self.pending_messages)
#             failed_count = len(self.failed_messages)
        
#         db_connected = False
#         if self.mqtt_db and hasattr(self.mqtt_db, 'pool'):
#             db_connected = self.mqtt_db.pool is not None
        
#         return {
#             'machine_id': self.machine_info['machine_id'],
#             'hostname': self.machine_info['hostname'],
#             'ip': self.machine_info['ip'],
#             'is_running': self.is_running,
#             'connected': self.client.is_connected(),
#             'reconnect_count': self.reconnect_count,
#             'last_connect': self.last_connect_time,
#             'db_connected': db_connected,
#             'db_ready': self.db_ready.is_set(),  # ✅ NOUVEAU
#             'pending_messages': pending_count,
#             'failed_messages': failed_count     # ✅ NOUVEAU
#         }

# mqtt_db_handler.py
import json
import logging
import threading
import queue
import mysql.connector
from mysql.connector import pooling
from datetime import datetime
import platform
import socket
import uuid
import hashlib
import time

import queue
import threading
import time
import logging
import json
import platform
import uuid
import hashlib
import socket
from datetime import datetime
import mysql.connector
from mysql.connector import pooling

import queue
import threading
import time
import logging
import json
import platform
import uuid
import hashlib
import socket
from datetime import datetime
import mysql.connector
from mysql.connector import pooling

class MQTTDBHandler:
    """Handler pour persister les messages MQTT bruts dans MySQL avec machine tracking"""
    
    def __init__(self):
        self.pool = None
        self.message_queue = queue.Queue()
        self.worker_thread = None
        self.is_running = True
        self.failed_inserts = 0  # ✅ Compteur d'échecs
        self.total_inserts = 0   # ✅ Compteur de succès
        
        # Infos machine pour cette instance
        self.machine_info = self._get_machine_info()
        
        # ✅ CHANGEMENT : Retry connexion avec backoff
        self.init_pool_with_retry()
        self.start_worker()
        
        # ✅ Démarrer monitoring pool
        self.start_pool_monitor()
        
        logging.info(f"✅ MQTTDBHandler initialisé pour machine: {self.machine_info['hostname']}")
    
    def _get_machine_info(self):
        """Récupère les informations uniques de la machine"""
        try:
            # Nom d'hôte
            hostname = platform.node()
            
            # Adresse MAC
            mac_num = hex(uuid.getnode()).replace('0x', '').upper()
            mac = ':'.join(mac_num[i:i+2] for i in range(0, 11, 2)) if len(mac_num) >= 12 else '00:00:00:00:00:00'
            
            # Adresse IP
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(('8.8.8.8', 80))
                ip = s.getsockname()[0]
                s.close()
            except:
                try:
                    ip = socket.gethostbyname(hostname)
                except:
                    ip = '127.0.0.1'
            
            # Générer un ID unique
            unique_string = f"{hostname}_{mac}_{ip}"
            machine_id = hashlib.md5(unique_string.encode()).hexdigest()[:12]
            
            machine_info = {
                'machine_id': f"PC_{machine_id}",
                'hostname': hostname,
                'ip': ip,
                'mac': mac,
                'system': platform.system(),
                'release': platform.release(),
                'processor': platform.processor()
            }
            
            return machine_info
            
        except Exception as e:
            logging.error(f"❌ Erreur récupération infos machine: {e}")
            return {
                'machine_id': f"PC_{uuid.uuid4().hex[:8]}",
                'hostname': 'unknown',
                'ip': '127.0.0.1',
                'mac': '00:00:00:00:00:00',
                'system': 'unknown',
                'release': 'unknown',
                'processor': 'unknown'
            }
    
    def get_db_config(self):
        """Retourne la configuration MySQL"""
        return {
            'pool_name': 'alert_pool',
            'pool_size': 5,
            'host': 'vps-a8840f7d.vps.ovh.net',
            'port': 3306,
            'database': 'zonex',
            'user': 'zonex_user',
            'password': 'besmelleh123'
        }
        
    def init_pool_with_retry(self, max_retries=30):
        """✅ SIMPLE : Initialise le pool avec retry - version minimaliste"""
        for attempt in range(max_retries):
            try:
                db_config = self.get_db_config()
                
                logging.info(f"🔗 Tentative {attempt + 1}/{max_retries} connexion MySQL: {db_config['host']}:{db_config['port']}")
                
                # ✅ CONFIGURATION MINIMALISTE
                self.pool = pooling.MySQLConnectionPool(
                    pool_name=db_config['pool_name'],
                    pool_size=db_config['pool_size'],
                    host=db_config['host'],
                    port=db_config['port'],
                    database=db_config['database'],
                    user=db_config['user'],
                    password=db_config['password'],
                    autocommit=True,
                    connection_timeout=10,
                    connect_timeout=10,
                    use_pure=True
                )
                
                # ✅ TEST SIMPLE
                conn = self.pool.get_connection()
                conn.ping(reconnect=True, attempts=1, delay=0)
                conn.close()
                
                logging.info(f"✅ Pool MySQL établi sur {db_config['host']}")
                return True
                    
            except Exception as e:
                error_msg = str(e)
                logging.error(f"❌ Tentative {attempt + 1} échouée: {error_msg}")
                
                if attempt < max_retries - 1:
                    wait_time = min((attempt + 1) * 2, 10)
                    logging.info(f"⏳ Retry dans {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    logging.error("❌ Impossible de se connecter à MySQL")
                    self.pool = None
                    return False

    def start_pool_monitor(self):
        """✅ NOUVEAU : Monitore et reconnecte le pool si nécessaire"""
        def monitor():
            while self.is_running:
                time.sleep(30)  # Vérifier toutes les 30 secondes
                
                if not self.pool:
                    logging.warning("⚠️ Pool MySQL perdu, tentative reconnexion...")
                    self.init_pool_with_retry()
                else:
                    # Tester la connexion avec ping (évite "unread result")
                    conn = None
                    try:
                        conn = self.pool.get_connection()
                        conn.ping(reconnect=True, attempts=1, delay=0)
                        logging.debug("💚 Pool MySQL OK")
                    except Exception as e:
                        logging.error(f"❌ Pool MySQL défaillant: {e}")
                        self.pool = None
                    finally:
                        if conn:
                            try:
                                conn.close()
                            except:
                                pass
        
        threading.Thread(target=monitor, daemon=True, name="MySQL-Pool-Monitor").start()
        logging.info("👁️ Monitoring pool MySQL démarré")

    def start_worker(self):
        """Démarre le worker pour traiter les messages en file d'attente"""
        self.worker_thread = threading.Thread(
            target=self._process_queue,
            daemon=True,
            name=f"MQTT-DB-Worker-{self.machine_info['hostname']}"
        )
        self.worker_thread.start()
        logging.info("👷 Worker DB MySQL démarré")

    def _process_queue(self):
        """Traite les messages de la file d'attente"""
        pause_until = None  # Timestamp jusqu'à quand la pause est active
        processed_count = 0
        
        while self.is_running:
            try:
                # Vérifier si on est en pause
                if pause_until and time.time() < pause_until:
                    time.sleep(1)
                    continue
                
                message_data = self.message_queue.get(timeout=1)
                if message_data is None:
                    break
                
                topic, payload, qos, retain, client_id, machine_info = message_data
                
                # ✅ LOG: Message récupéré de la queue
                processed_count += 1
                queue_size = self.message_queue.qsize()
                logging.info(f"📥 [DB Worker] Traitement message #{processed_count}: {topic[:50]}... (queue: {queue_size})")
                
                # ✅ VÉRIFICATION CRITIQUE : Attendre que le pool soit disponible
                if not self.pool:
                    logging.error("❌ [DB Worker] Pool MySQL indisponible, mise en pause de 30 secondes...")
                    pause_until = time.time() + 30
                    # Remettre le message dans la queue
                    self.message_queue.put(message_data)
                    self.message_queue.task_done()
                    continue
                
                # Réinitialiser la pause si le pool est disponible
                pause_until = None
                
                # ✅ LOG: Début du traitement
                start_time = time.time()
                
                # ✅ Retry avec backoff
                max_retries = 30
                for attempt in range(max_retries):
                    logging.info(f"🔄 [DB Worker] Tentative {attempt + 1}/{max_retries} pour {topic[:50]}...")
                    success = self._save_to_db(topic, payload, qos, retain, client_id, machine_info)
                    
                    if success:
                        self.total_inserts += 1
                        processing_time = time.time() - start_time
                        logging.info(f"✅ [DB Worker] Message sauvegardé en {processing_time:.2f}s: {topic[:50]}...")
                        break
                    else:
                        self.failed_inserts += 1
                        
                        if attempt < max_retries - 1:
                            wait_time = (attempt + 1) * 1  # 1s, 2s, 3s
                            logging.warning(f"⚠️ [DB Worker] Retry {attempt + 1}/{max_retries} dans {wait_time}s...")
                            time.sleep(wait_time)
                        else:
                            logging.error(f"❌ [DB Worker] CRITIQUE : Message PERDU après {max_retries} tentatives: {topic[:50]}...")
                
                self.message_queue.task_done()
                
                # ✅ Log stats périodiquement
                if (self.total_inserts + self.failed_inserts) % 10 == 0:  # Tous les 10 messages
                    total = self.total_inserts + self.failed_inserts
                    if total > 0:
                        success_rate = (self.total_inserts / total) * 100
                        logging.info(f"📊 [DB Stats] {self.total_inserts} succès, {self.failed_inserts} échecs ({success_rate:.1f}% succès) - Queue: {queue_size}")
                
            except queue.Empty:
                # ✅ LOG: Queue vide
                if time.time() % 30 < 1:  # Toutes les 30 secondes environ
                    logging.debug("⏳ [DB Worker] Queue vide en attente...")
                continue
            except Exception as e:
                logging.error(f"❌ [DB Worker] Erreur traitement queue DB: {e}", exc_info=True)
                time.sleep(1)

    def _save_to_db(self, topic: str, payload: dict, qos: int, retain: bool, 
                    client_id: str = None, machine_info: dict = None):
        """Sauvegarde effectivement dans MySQL - UNIQUEMENT INSERTION"""
        if not self.pool:
            logging.error("⚠️ [_save_to_db] Pool MySQL non disponible")
            return False
        
        conn = None
        cursor = None
        try:
            # ✅ LOG: Début de l'insertion
            logging.debug(f"💾 [_save_to_db] Début insertion: {topic[:50]}...")
            
            # ✅ Timeout sur get_connection
            conn_start = time.time()
            conn = self.pool.get_connection()
            conn_time = time.time() - conn_start
            
            if conn_time > 1:  # Log si c'est lent
                logging.warning(f"⏱️ [_save_to_db] Get connection lent: {conn_time:.2f}s")
            
            if not conn:
                logging.error("❌ [_save_to_db] Impossible d'obtenir une connexion du pool")
                return False
            
            cursor = conn.cursor()
            
            # Déterminer si c'est un JSON valide
            is_valid_json = True
            json_payload = payload
            
            if isinstance(payload, str):
                try:
                    json_payload = json.loads(payload)
                    logging.debug(f"📄 [_save_to_db] JSON validé: {len(payload)} chars")
                except:
                    is_valid_json = False
                    json_payload = {"raw_data": payload}
                    logging.warning(f"⚠️ [_save_to_db] JSON invalide, conversion en raw_data")
            
            # Préparer les valeurs
            company_id = self._extract_company_id(json_payload)
            if not company_id:
                try:
                    from simple_notifier import CONFIG
                    company_id = CONFIG.get('company_id', 'default')
                    logging.debug(f"🏢 [_save_to_db] Company ID from CONFIG: {company_id}")
                except:
                    company_id = 'default'
                    logging.debug(f"🏢 [_save_to_db] Company ID default: {company_id}")
            
            received_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            if not machine_info:
                machine_info = self.machine_info
            
            # ✅ LOG: Avant insertion
            logging.debug(f"📤 [_save_to_db] Insertion pour machine: {machine_info.get('hostname')}")
            
            # ✅ INSERTION DIRECTE sans vérification de table
            insert_start = time.time()
            cursor.execute("""
                INSERT INTO mqtt_messages 
                (topic, payload, qos, retain, client_id, 
                machine_id, machine_name, machine_ip, machine_mac,
                company_id, received_at, error, error_message)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                topic,
                json.dumps(json_payload),
                qos,
                1 if retain else 0,
                client_id,
                machine_info.get('machine_id'),
                machine_info.get('hostname'),
                machine_info.get('ip'),
                machine_info.get('mac'),
                company_id,
                received_at,
                1 if not is_valid_json else 0,
                "Invalid JSON" if not is_valid_json else None
            ))
            
            insert_time = time.time() - insert_start
            if insert_time > 1:  # Log si c'est lent
                logging.warning(f"⏱️ [_save_to_db] Insertion lente: {insert_time:.2f}s")
            
            msg_id = cursor.lastrowid
            total_time = time.time() - conn_start
            
            logging.info(f"✅ [_save_to_db] Message {msg_id} sauvegardé en {total_time:.2f}s (machine: {machine_info.get('hostname')}, topic: {topic[:50]}...)")
            
            return True
            
        except mysql.connector.Error as e:
            # ✅ Gestion spécifique des erreurs MySQL
            if e.errno == 1146:  # Table doesn't exist
                logging.error("❌ [_save_to_db] Table 'mqtt_messages' n'existe pas. Veuillez la créer manuellement.")
            elif e.errno in (2003, 2006, 2013, 2055):  # Lost connection
                logging.error(f"❌ [_save_to_db] Connexion MySQL perdue: {e}")
                self.pool = None
            else:
                logging.error(f"❌ [_save_to_db] Erreur MySQL [{e.errno}]: {e.msg}")
            
            return False
            
        except Exception as e:
            logging.error(f"❌ [_save_to_db] Erreur sauvegarde MySQL: {e}", exc_info=True)
            return False
            
        finally:
            # ✅ NETTOYAGE GARANTI
            if cursor:
                try:
                    cursor.close()
                except:
                    pass
            if conn:
                try:
                    conn.close()
                except:
                    pass

    def save_message_async(self, topic: str, payload: dict, qos: int = 0, 
                        retain: bool = False, client_id: str = None,
                        machine_info: dict = None):
        """Ajoute un message à la file d'attente pour sauvegarde asynchrone"""
        try:
            if machine_info is None:
                machine_info = self.machine_info
            
            # ✅ Vérifier la taille de la queue
            queue_size = self.message_queue.qsize()
            
            # ✅ LOG IMPORTANT
            payload_size = len(str(payload)) if isinstance(payload, (str, dict, list)) else 0
            logging.info(f"📝 [save_message_async] Ajout à queue DB: {topic[:50]}... (taille queue: {queue_size + 1}, payload: {payload_size} bytes)")
            
            if queue_size > 1000:
                logging.warning(f"⚠️ [save_message_async] Queue DB surchargée: {queue_size} messages en attente")
            
            self.message_queue.put((topic, payload, qos, retain, client_id, machine_info))
            
            # ✅ LOG de confirmation
            logging.debug(f"✅ [save_message_async] Message ajouté à la queue: {topic[:50]}...")
            
            return True
            
        except Exception as e:
            logging.error(f"❌ [save_message_async] Erreur ajout à la queue: {e}", exc_info=True)
            return False


    def _extract_company_id(self, payload):
        """Essaie d'extraire le company_id du payload"""
        try:
            if isinstance(payload, dict):
                # Chercher dans différentes structures
                if 'company' in payload:
                    return str(payload['company'])
                elif 'company_id' in payload:
                    return str(payload['company_id'])
                
                # Chercher récursivement
                for key, value in payload.items():
                    if isinstance(value, dict):
                        result = self._extract_company_id(value)
                        if result:
                            return result
                    elif isinstance(value, list):
                        for item in value:
                            result = self._extract_company_id(item)
                            if result:
                                return result
            elif isinstance(payload, list) and len(payload) > 0:
                return self._extract_company_id(payload[0])
        except:
            pass
        return None
    

    def get_stats(self):
        """Récupère les statistiques de la DB - Version simplifiée"""
        if not self.pool:
            return {
                "status": "not_connected",
                "total_inserts": self.total_inserts,
                "failed_inserts": self.failed_inserts,
                "queue_size": self.message_queue.qsize(),
                "message": "Pool MySQL non disponible"
            }
        
        total = self.total_inserts + self.failed_inserts
        success_rate = (self.total_inserts / total * 100) if total > 0 else 0
        
        return {
            "status": "connected",
            "total_inserts": self.total_inserts,
            "failed_inserts": self.failed_inserts,
            "success_rate": f"{success_rate:.1f}%",
            "queue_size": self.message_queue.qsize(),
            "machine": self.machine_info['hostname']
        }
    
    def stop(self):
        """Arrête proprement le handler"""
        logging.info(f"🛑 Arrêt MQTTDBHandler...")
        self.is_running = False
        
        # ✅ Attendre que la queue soit vide
        queue_size = self.message_queue.qsize()
        if queue_size > 0:
            logging.info(f"⏳ Attente vidage queue ({queue_size} messages)...")
            self.message_queue.join()
        
        if self.worker_thread:
            self.worker_thread.join(timeout=10)
        
        # ✅ Log stats finales
        total = self.total_inserts + self.failed_inserts
        if total > 0:
            success_rate = (self.total_inserts / total) * 100
            logging.info(f"📊 Stats finales: {self.total_inserts} succès, {self.failed_inserts} échecs ({success_rate:.1f}% succès)")
        logging.info("✅ MQTTDBHandler arrêté")

SOCKET_PORT = 56789
SOCKET_ADDR = ("127.0.0.1", SOCKET_PORT)
LOCK_FILE = Path(tempfile.gettempdir()) / "zonex_notifier.lock"

def is_app_already_running():
    """Empêche plusieurs instances"""
    logging.info("🔍 Vérification instance")
    
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(SOCKET_ADDR)
        server_socket.listen(1)
        logging.debug("✅ Port disponible")
    except OSError:
        logging.warning("⚠️ Instance existante détectée")
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(SOCKET_ADDR)
            s.sendall(b"SHOW")
            s.close()
            logging.info("🪟 Fenêtre demandée")
        except Exception as e:
            logging.error(f"⚠️ Impossible de contacter instance: {e}")
        return True

    with open(LOCK_FILE, "w") as f:
        f.write(str(os.getpid()))
    logging.debug(f"📝 PID écrit: {os.getpid()}")

    def cleanup():
        try:
            logging.debug("🧹 Nettoyage ressources")
            server_socket.close()
            LOCK_FILE.unlink(missing_ok=True)
        except Exception as e:
            logging.warning(f"⚠️ Erreur cleanup: {e}")

    atexit.register(cleanup)

    def socket_listener():
        logging.debug("👂 Démarrage écoute socket")
        while True:
            conn, _ = server_socket.accept()
            data = conn.recv(1024)
            if data == b"SHOW":
                logging.info("📨 Reçu 'SHOW'")
                reopen_interface()
            conn.close()

    threading.Thread(target=socket_listener, daemon=True).start()
    
    logging.info("✅ Première instance")

    return False

from pystray import Icon, Menu, MenuItem
from PIL import Image

def reopen_interface():
    """Réaffiche l'interface principale"""
    logging.info("🔄 Réouverture interface")
    
    if tk._default_root and tk._default_root.winfo_exists():
        logging.debug("🪟 Fenêtre existante - remise au premier plan")
        main_window.root.after(0, lambda: bring_window_to_front_enhanced(main_window.root))
        main_window.root.after(0, main_window.update_alerts_list)
    else:
        logging.info("🆕 Création nouvelle fenêtre")
        root = tk.Tk()
        app = MainWindow(root)
        root.mainloop()
        
def create_tray_icon():
    """Crée icône barre système"""
    try:
        logging.info("🖥️ Création icône tray")
        
        # Obtenir le répertoire du script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(script_dir, "zonex.ico")
        
        # Si .ico n'existe pas, essayer .png
        if not os.path.exists(icon_path):
            icon_path = os.path.join(script_dir, "zonex.png")
        
        # Si toujours pas trouvé, créer une icône par défaut
        if not os.path.exists(icon_path):
            logging.info("⚠️ Aucune icône trouvée, création icône par défaut")
            image = Image.new('RGB', (64, 64), color='#2563eb')
        else:
            image = Image.open(icon_path)

        def on_show(icon, item):
            logging.info("📋 Ouvrir sélectionné")
            reopen_interface()

        def on_exit(icon, item):
            logging.info("🚪 Quitter sélectionné")
            icon.stop()
            os._exit(0)

        menu = Menu(
            MenuItem(f"Ouvrir {CONFIG['app_name']}", on_show),
        )

        tray_icon = Icon(f"{CONFIG['app_name']}", image, f"{CONFIG['app_name']}", menu)
        tray_icon.run_detached()
        logging.info("✅ Icône tray créée")
    except Exception as e:
        logging.warning(f"⚠️ Erreur icône tray (non bloquante): {e}")
 
import sys
import warnings

# Supprimer les warnings
warnings.filterwarnings("ignore", category=UserWarning, module="win10toast_click")
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Filtrer les erreurs WNDPROC dans stderr
class StderrFilter:
    def __init__(self, stream):
        self.stream = stream
    
    def write(self, text):
        # Ignorer les erreurs WNDPROC
        if self.stream is not None:  # Vérifier si le stream existe
            if "WNDPROC" not in text and "WPARAM" not in text and "LRESULT" not in text:
                try:
                    self.stream.write(text)
                except:
                    pass  # Ignorer silencieusement les erreurs
    
    def flush(self):
        if self.stream is not None:
            try:
                self.stream.flush()
            except:
                pass

# Appliquer le filtre seulement si stderr existe
if sys.stderr is not None:
    sys.stderr = StderrFilter(sys.stderr)       
if __name__ == "__main__":
    logging.info("🚀 Démarrage Simple Notifier")
    
    if is_app_already_running():
        logging.warning("❌ Application déjà en cours")
        sys.exit(0)
    
    add_to_startup("SimpleNotifier")
    logging.info("✅ Ajouté au démarrage")

    if not load_config() or not CONFIG.get('company_id'):
        logging.info("🔐 Authentification requise")
        login_window = LoginWindow()
        login_window.root.mainloop()
        
        if not CONFIG.get('company_id'):
            logging.error("❌ Authentification requise")
            sys.exit(1)
    
    logging.info(f"🎯 Démarrage - Société: {CONFIG['company_id']}")
    logging.info(f"👤 Utilisateur: {CONFIG.get('user_email')}")
    logging.info(f"📡 Topic: {CONFIG['mqtt_topic']}")
    logging.info("🔄 En attente de messages...")
    logging.info("📡 Démarrage MQTT listener")
    logging.info("🏗️ Création fenêtre principale")
    main_window = MainWindow()
    mqtt_listener = MQTTListener(main_window)
    mqtt_listener.start()
    show_startup_notification()
    threading.Thread(target=create_tray_icon, daemon=True).start()

    logging.info("👷 Démarrage worker notifications")
    notification_thread = threading.Thread(target=notification_worker)
    notification_thread.daemon = True
    notification_thread.start()





    logging.info("🎬 Démarrage boucle Tkinter")
    main_window.root.mainloop()

    try:
        logging.info("⏳ Boucle d'attente démarrée")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("🛑 Arrêt demandé (Ctrl+C)")
        print("Arrêt demandé")
        print("\nArrêt en cours...")
        stop_notification_worker()
        sys.exit(0)