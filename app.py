# -*- coding: utf-8 -*-
import os
import io
import base64
import pandas as pd
import numpy as np
import matplotlib
# Usar backend no interactivo ANTES de importar pyplot
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import datetime
import traceback
import uuid
# --- IMPORTACIONES PARA LOGIN Y BD ---
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
# Usar bcrypt directamente
import bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
# --- FIN IMPORTACIONES LOGIN Y BD ---
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, make_response, send_file # Añadido send_file
from werkzeug.utils import secure_filename
# Importar urlparse desde urllib.parse
from urllib.parse import urlparse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
# Importa tus clases manager (Asegúrate que estos archivos existan y sean correctos)
try:
    from data_manager import DataManager
    from threat_simulator import ThreatSimulator
    from threat_detector import ThreatDetector
    from alert_manager import AlertManager
    from admin_manager import AdminManager
    print("DEBUG: Clases Manager importadas OK.")
except ImportError as e:
    print(f"FATAL ERROR: No se pudo importar clase manager: {e}")
    print("Asegúrate que los archivos .py de las clases (data_manager.py, etc.) estén en la misma carpeta que app.py o sean instalables.")
    exit()
# Importar wraps
from functools import wraps

print("DEBUG: Definiendo decorador admin_required...")
# Decorador para rutas de admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verificar autenticación Y si el usuario tiene el atributo is_admin y es True
        if not current_user.is_authenticated or not hasattr(current_user, 'is_admin') or not current_user.is_admin:
            flash("Acceso no autorizado. Solo para administradores.", "error")
            return redirect(url_for('dashboard')) # Redirigir a dashboard o login
        return f(*args, **kwargs)
    return decorated_function

# --- Configuración de la App ---
print("DEBUG: Creando instancia de Flask app...")
app = Flask(__name__)
print("DEBUG: Instancia Flask creada.")
# Usa una clave secreta más segura y léela desde variables de entorno si es posible
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "d3v3l0pm3nt_s3cr3t_k3y_pl34s3_ch4ng3_v6") # Cambia esto
# Carpetas (Usar rutas absolutas o relativas seguras)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
TEMP_SIM_FOLDER = os.path.join(BASE_DIR, 'temp_sim_data')
SAVED_PLOTS_FOLDER = os.path.join(BASE_DIR, 'saved_plots') # Carpeta para guardar gráficos
# Asegúrate que MODEL_DIR sea consistente con ThreatDetector
MODEL_DIR = os.path.join(BASE_DIR, 'models') # <<<< Asegúrate que esta sea la carpeta correcta
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TEMP_SIM_FOLDER'] = TEMP_SIM_FOLDER
app.config['SAVED_PLOTS_FOLDER'] = SAVED_PLOTS_FOLDER
app.config['MODEL_FOLDER'] = MODEL_DIR # <<< Añadir configuración para la carpeta de modelos
app.config['ALLOWED_EXTENSIONS'] = {'csv'}

print(f"DEBUG: Carpetas configuradas: UPLOAD={app.config['UPLOAD_FOLDER']}, TEMP_SIM={app.config['TEMP_SIM_FOLDER']}, PLOTS={app.config['SAVED_PLOTS_FOLDER']}, MODELS={app.config['MODEL_FOLDER']}")

# --- CONFIGURACIÓN DE BASE DE DATOS ---
DB_USER = os.environ.get("DB_USER", "root") # Lee de variable de entorno o usa default
DB_PASS = os.environ.get("DB_PASS", "") # Ajusta si tienes contraseña para root en XAMPP
DB_HOST = os.environ.get("DB_HOST", "localhost") # Correcto para XAMPP por defecto
DB_NAME = os.environ.get("DB_NAME", "cyber_db") # La base de datos que creaste
# Asegúrate de usar mysql+mysqlconnector si instalaste mysql-connector-python
db_uri = f'mysql+mysqlconnector://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}'
print(f"DEBUG: Configurando URI de BD: {db_uri[:db_uri.find('@')+1]}********")
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False # Poner True para ver queries SQL (útil para debug)

# --- INICIALIZACIÓN DE EXTENSIONES ---
print("DEBUG: Inicializando SQLAlchemy...")
try:
    db = SQLAlchemy(app)
    print("DEBUG: SQLAlchemy inicializado.")
except Exception as e_sql:
    print(f"FATAL ERROR: Inicializando SQLAlchemy: {e_sql}")
    exit()

print("DEBUG: Inicializando LoginManager...")
try:
    login_manager = LoginManager(app)
    print(f"DEBUG: LoginManager instanciado: {login_manager}")
    login_manager.login_view = 'login' # Ruta a la que redirigir si se necesita login
    login_manager.login_message = "Por favor, inicia sesión para acceder a esta página."
    login_manager.login_message_category = "info"
    print("DEBUG: Configuración LoginManager completa.")
except Exception as e_login:
    print(f"FATAL ERROR: Inicializando LoginManager: {e_login}")
    exit()

# Crear directorios si no existen
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['TEMP_SIM_FOLDER'], exist_ok=True)
os.makedirs(app.config['SAVED_PLOTS_FOLDER'], exist_ok=True)
os.makedirs(app.config['MODEL_FOLDER'], exist_ok=True) # <<< Asegurar que carpeta de modelos exista

# --- Instancias Globales (Managers) ---
# system_config = {'glm_threshold': 0.7} # Configuración global inicial - Cargar después

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

try:
    print("DEBUG: Inicializando Managers...")
    # Asegúrate que las clases Manager estén definidas correctamente en sus archivos
    data_manager = DataManager(upload_folder='uploads', processed_filename='datos_preprocesados.csv') # Pasar config si es necesario
    simulator = ThreatSimulator()
    alert_manager = AlertManager()
    # Pasar la carpeta correcta al detector
    detector = ThreatDetector(model_dir=app.config['MODEL_FOLDER']) # <<< Pasar config de carpeta
    # Pasar el detector al admin manager si es necesario
    admin_manager = AdminManager(detector_instance=detector) # Asume que admin_manager existe y acepta detector
    print("DEBUG: Managers inicializados.")
    # Cargar configuración del sistema DESPUÉS de inicializar managers si dependen de ella
    # Intenta cargar desde admin manager o usa un default
    if hasattr(admin_manager, 'load_system_config'):
        system_config = admin_manager.load_system_config()
        print(f"DEBUG: Configuración del sistema cargada desde AdminManager: {system_config}")
    else:
        # Si admin_manager no maneja la config, carga/inicializa aquí
        # Ejemplo: system_config = load_config_from_file() or {'glm_threshold': 0.7}
        system_config = {'glm_threshold': 0.7} # << AJUSTA ESTO si es necesario
        print(f"DEBUG: Configuración del sistema inicializada por defecto: {system_config}")
    # Asegurar que el detector tenga el umbral inicial
    if hasattr(detector, 'prediction_threshold'):
        detector.prediction_threshold = system_config.get('glm_threshold', 0.7)

except NameError as ne:
     print(f"FATAL ERROR: Parece que una clase Manager no está definida o importada: {ne}")
     exit()
except Exception as e:
    print(f"FATAL ERROR inicializando manager o cargando config: {e}\n{traceback.format_exc()}")
    exit()

# --- MODELO DE BASE DE DATOS (USUARIO) ---
print("DEBUG: Definiendo modelo User...")
# (Tu clase User como la tenías)
class User(db.Model, UserMixin):
    __tablename__ = 'users' # Nombre explícito de la tabla
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False) # bcrypt hashes son de 60 chars
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def set_password(self, password):
        try:
            password_bytes = password.encode('utf-8')
            salt = bcrypt.gensalt()
            self.password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
        except Exception as e:
            print(f"Error al hashear la contraseña para {self.username}: {e}")
            raise ValueError("Error al establecer la contraseña") from e

    def check_password(self, password):
        if not self.password_hash:
            print(f"WARN: Intento de verificar contraseña sin hash para usuario {self.id}")
            return False
        try:
            password_bytes = password.encode('utf-8')
            stored_hash_bytes = self.password_hash.encode('utf-8')
            return bcrypt.checkpw(password_bytes, stored_hash_bytes)
        except ValueError as ve:
            print(f"ERROR (ValueError) al verificar contraseña para usuario {self.id}: {ve}. Hash inválido?")
            return False
        except Exception as e:
            print(f"ERROR general al verificar contraseña para usuario {self.id}: {e}")
            return False

    def __repr__(self):
        return f'<User {self.username}>'

print("DEBUG: Modelo User definido.")

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    """ Carga un usuario dado su ID para Flask-Login. """
    # (Tu código existente para load_user)
    print(f"DEBUG: load_user llamado para ID: {user_id}")
    try:
        user = db.session.get(User, int(user_id))
        if user: print(f"DEBUG: Usuario {user.username} encontrado.")
        else: print(f"DEBUG: Usuario ID {user_id} no encontrado.")
        return user
    except ValueError: print(f"ERROR: ID de usuario inválido: {user_id}"); return None
    except Exception as e: print(f"ERROR cargando usuario ID {user_id}: {e}"); return None


# --- FORMULARIOS (Flask-WTF) ---
print("DEBUG: Definiendo Formularios...")
# (Tus clases LoginForm, RegistrationForm, UserAdminForm, DeleteUserForm como las tenías)
class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    remember_me = BooleanField('Recuérdame')
    submit = SubmitField('Iniciar Sesión')

class RegistrationForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirmar Contraseña', validators=[DataRequired(), EqualTo('password', message='Las contraseñas no coinciden.')])
    submit = SubmitField('Registrarse')
    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Este nombre de usuario ya existe. Por favor, elige otro.')
    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Este email ya está registrado. Por favor, usa otro.')

class UserAdminForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Nueva Contraseña (dejar vacío para no cambiar)')
    is_admin = BooleanField('Es Administrador')
    submit = SubmitField('Guardar Usuario')
    def __init__(self, original_username=None, original_email=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email
    def validate_username(self, username):
        if username.data != self.original_username:
            if User.query.filter_by(username=username.data).first():
                raise ValidationError('Este nombre de usuario ya existe.')
    def validate_email(self, email):
        if email.data != self.original_email:
            if User.query.filter_by(email=email.data).first():
                raise ValidationError('Este email ya está registrado.')

class DeleteUserForm(FlaskForm):
    submit = SubmitField('Eliminar Usuario')

print("DEBUG: Formularios definidos.")


# --- Context Processor ---
@app.context_processor
def inject_global_vars():
    return {'current_year': datetime.datetime.now().year,
            'now': datetime.datetime.now}

# --- Filtro Jinja2 para Fechas ---
@app.template_filter('format_datetime')
def format_datetime_filter(value, format='%Y-%m-%d %H:%M:%S'):
    # (Tu código existente para format_datetime_filter)
    if not value: return "N/A"
    if isinstance(value, str):
        try:
            if '.' in value: dt = datetime.datetime.fromisoformat(value.split('.')[0])
            else: dt = datetime.datetime.fromisoformat(value)
            return dt.strftime(format)
        except ValueError:
            for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S'):
                 try: dt = datetime.datetime.strptime(value, fmt); return dt.strftime(format)
                 except ValueError: pass
            print(f"WARN: format_datetime no pudo parsear string: {value}"); return value
    elif isinstance(value, datetime.datetime):
         try: return value.strftime(format)
         except Exception as e_fmt: print(f"WARN: format_datetime err formateando dt: {e_fmt}"); return str(value)
    else: print(f"WARN: format_datetime recibió tipo inesperado: {type(value)}"); return str(value)


# --- Funciones de Reporte ---
print("DEBUG: Definiendo funciones de reporte...")
# (Tu función generate_last_detection_csv como la tenías)
def generate_last_detection_csv(results):
    if not results: return None
    output = io.StringIO()
    try:
        output.write(f"Reporte Última Detección\n")
        output.write(f"Timestamp,{results.get('ts', 'N/A')}\n")
        output.write(f"Fuente Datos,{results.get('src', 'N/A')}\n")
        output.write(f"Filas Analizadas,{results.get('rows', 'N/A')}\n")
        output.write(f"Umbral GLM,{results.get('thr', 'N/A')}\n\n")
        metrics = results.get('metrics', {})
        if metrics:
            output.write("Metricas Modelo:\nMetrica,Valor\n")
            simple_metrics = {k: v for k, v in metrics.items() if isinstance(v, (int, float, str, bool)) and k not in ['report', 'confusion_matrix', 'classes']}
            for name, value in simple_metrics.items(): output.write(f"{name.replace('_', ' ').title()},{value}\n")
            report = metrics.get('report', {})
            if report and isinstance(report, dict):
                output.write("\nReporte Clasificacion:\n")
                try: pd.DataFrame(report).transpose().to_csv(output, index=True, header=True, float_format='%.4f')
                except Exception as e_rep_csv: output.write(f"Error_generando_reporte_clasificacion,{e_rep_csv}\n")
            cm = metrics.get('confusion_matrix')
            if cm is not None:
                output.write("\nMatriz Confusion:\n")
                try:
                    cm_arr = np.array(cm); classes = metrics.get('classes', ['BENIGN', 'ATTACK'])
                    output.write("," + ",".join([f"Prediccion {c}" for c in classes]) + "\n")
                    for i, row_data in enumerate(cm_arr): output.write(f"Real {classes[i]}," + ",".join(map(str, row_data)) + "\n")
                except Exception as e_cm_csv: output.write(f"Error_generando_matriz_confusion,{e_cm_csv}\n")
        summary = results.get('summary', {})
        if summary:
            output.write("\nResumen Detecciones:\nEtiqueta,Cantidad\n")
            for label, count in summary.items(): output.write(f"{label},{count}\n")
        head = results.get('head', [])
        if head:
            output.write("\nVista Previa Resultados (Primeras Filas):\n")
            try: pd.DataFrame(head).to_csv(output, index=False, header=True)
            except Exception as e_head_csv: output.write(f"Error_generando_vista_previa,{e_head_csv}\n")
        output.seek(0)
        return output.getvalue()
    except Exception as e_csv: print(f"Error generando CSV completo: {e_csv}"); return None

print("DEBUG: Funciones reporte OK.")


# --- Helper para Gráficos ---
print("DEBUG: Definiendo funciones gráficos...")
# (Tu función generate_plot_base64_and_save como la tenías)
def generate_plot_base64_and_save(plot_func, *args, **kwargs):
    img_buffer = io.BytesIO(); fig = None; filename = None; filepath = None
    save_dir = kwargs.pop('save_dir', app.config.get('SAVED_PLOTS_FOLDER', os.path.join(BASE_DIR, 'saved_plots')))
    save_plot = kwargs.pop('save_plot', True)
    try:
        fig = plt.figure(figsize=kwargs.pop('figsize', (6, 4)))
        plot_func(fig=fig, *args, **kwargs)
        plt.tight_layout()
        plt.savefig(img_buffer, format='png', bbox_inches='tight')
        img_buffer.seek(0)
        base64_url = f"data:image/png;base64,{base64.b64encode(img_buffer.getvalue()).decode('utf8')}"
        if save_plot:
            if not save_dir: print("WARN plot_save: Directorio para guardar gráficos (save_dir) no configurado.")
            else:
                os.makedirs(save_dir, exist_ok=True); ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                base_filename_raw = kwargs.get('title', 'plot').replace(' ', '_')
                base_filename = "".join(c for c in base_filename_raw if c.isalnum() or c in ('_', '-')).rstrip() or "plot"
                filename = f"{base_filename}_{ts}.png"; filepath = os.path.join(save_dir, filename)
                try:
                    with open(filepath, 'wb') as f: f.write(img_buffer.getvalue())
                    print(f"INFO: Gráfico guardado en: {filepath}")
                except Exception as e_save: print(f"ERROR al guardar gráfico en archivo {filepath}: {e_save}"); filename = None
        return base64_url, filename
    except Exception as e: print(f"ERROR generando/guardando plot: {e}\n{traceback.format_exc()}"); return None, None
    finally:
        if fig: plt.close(fig)

# (Tu función plot_confusion_matrix_func como la tenías)
def plot_confusion_matrix_func(cm, fig, classes=None, title='Matriz Confusión'):
    if classes is None: classes = ['BENIGN', 'ATTACK']
    ax = fig.add_subplot(111); cm_arr = np.array(cm)
    sns.heatmap(cm_arr, annot=True, fmt='d', cmap='Blues', ax=ax, cbar=False, xticklabels=classes, yticklabels=classes, annot_kws={"size": 10})
    ax.set_xlabel('Predicción'); ax.set_ylabel('Real'); ax.set_title(title)

print("DEBUG: Funciones gráficos OK.")


# --- RUTAS AUTENTICACIÓN ---
# (Tu código existente para /login, /logout, /register)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data); flash(f'Inicio de sesión exitoso para {user.username}.', 'success')
            next_page = request.args.get('next')
            if next_page and urlparse(next_page).netloc == '': print(f"DEBUG: Redirigiendo a 'next' page: {next_page}"); return redirect(next_page)
            else: print("DEBUG: Redirigiendo al dashboard."); return redirect(url_for('dashboard'))
        else: flash('Login fallido. Verifica usuario y contraseña.', 'error'); print(f"WARN: Login fallido para usuario: {form.username.data}")
    return render_template('login.html', title='Iniciar Sesión', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user(); flash('Has cerrado sesión correctamente.', 'info'); print("INFO: Usuario cerró sesión."); return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            user = User(username=form.username.data, email=form.email.data); user.set_password(form.password.data)
            user.is_admin = (User.query.count() == 0); db.session.add(user); db.session.commit()
            flash(f'¡Cuenta creada para {form.username.data}! Ahora puedes iniciar sesión.', 'success')
            print(f"INFO: Nuevo usuario registrado: {form.username.data}{' (admin)' if user.is_admin else ''}")
            return redirect(url_for('login'))
        except ValidationError as ve: print(f"WARN: Error de validación en registro: {ve}")
        except Exception as e:
            db.session.rollback(); err_msg = str(e)
            if 'Duplicate entry' in err_msg:
                if f"'{form.username.data}'" in err_msg and 'for key \'users.username\'' in err_msg: flash('Error: El nombre de usuario ya existe.', 'error')
                elif f"'{form.email.data}'" in err_msg and 'for key \'users.email\'' in err_msg: flash('Error: El email ya está registrado.', 'error')
                else: flash(f'Error de base de datos (duplicado): {err_msg}', 'error')
            else: flash(f'Error al crear la cuenta: {err_msg}', 'error')
            print(f"ERROR al registrar usuario {form.username.data}: {e}\n{traceback.format_exc()}")
        return render_template('register.html', title='Registro', form=form)
    return render_template('register.html', title='Registro', form=form)


# --- RUTAS PRINCIPALES ---
# (Tu código existente para /dashboard, /data, /simulate)
@app.route('/')
@login_required
def dashboard():
    print("DEBUG: Accediendo a /dashboard"); active_alerts = []; last_detection = None; model_status = "No Disponible"; recent_alerts = []
    try:
        active_alerts = alert_manager.get_alerts(show_all=False); detection_history = alert_manager.get_detection_history()
        last_detection = detection_history[-1] if detection_history else None
        print(f"DEBUG: Contenido de 'last_detection' para dashboard: {last_detection}")
        model_is_loaded = (detector is not None and hasattr(detector, 'model') and detector.model is not None)
        model_status = "Modelo Cargado  ✅ " if model_is_loaded else "Modelo No Cargado  ❌ "
        all_alerts_sorted = alert_manager.get_alerts(show_all=True); recent_alerts = all_alerts_sorted[:5]
        print(f"DEBUG: Dashboard - Alertas Activas: {len(active_alerts)}, Última Detección: {'Sí' if last_detection else 'No'}, Estado Modelo: {model_status}")
    except AttributeError as ae: print(f"ERROR: Atributo/Método faltante en manager para dashboard: {ae}"); flash(f"Error interno: Falta método/atributo en manager ({ae}). Contacta al administrador.", "danger"); model_status = "Error Interno"
    except Exception as e: print(f"ERROR cargando datos del dashboard: {e}\n{traceback.format_exc()}"); flash("Error al cargar los datos del dashboard.", "error"); active_alerts, last_detection, model_status, recent_alerts = [], None, "Error", []
    return render_template('dashboard.html', active_alerts_count=len(active_alerts), last_detection=last_detection, model_status=model_status, recent_alerts=recent_alerts)

@app.route('/data', methods=['GET', 'POST'])
@login_required
def manage_data():
    if request.method == 'POST':
        action = request.form.get('action'); url = url_for('manage_data')
        try:
            if action == 'upload':
                if 'file' not in request.files: flash('No se incluyó el archivo en la solicitud.', 'error'); return redirect(url)
                file = request.files['file']; fname = file.filename
                if fname == '': flash('No se seleccionó ningún archivo.', 'warning'); return redirect(url)
                if file and allowed_file(fname):
                    fname = secure_filename(fname); fpath = os.path.join(app.config['UPLOAD_FOLDER'], fname); file.save(fpath)
                    ok, result = data_manager.load_csv_data(fpath)
                    if ok: flash(f"Archivo '{fname}' cargado.", 'success'); session['loaded_filepath'] = fpath; session.pop('processed_data_info', None)
                    else: flash(f"Error al cargar '{fname}': {result}", 'error'); session.pop('loaded_filepath', None)
                elif file: flash(f"Tipo de archivo no permitido: '{fname}'. Solo CSV.", 'error')
            elif action == 'preprocess':
                df_loaded = data_manager.get_loaded_data()
                if df_loaded is not None and not df_loaded.empty:
                    print("INFO: Intentando preprocesar datos cargados...")
                    try:
                        processed_df_result, msg = data_manager.preprocess_data(df_loaded.copy()) # Pasar copia
                        if processed_df_result is not None:
                            flash(msg, 'success')
                            session['processed_data_info'] = {'rows': len(processed_df_result), 'cols': len(processed_df_result.columns), 'ts': datetime.datetime.now().isoformat(timespec='seconds'), 'source_file': os.path.basename(session.get('loaded_filepath', 'N/A'))}
                            print(f"DEBUG: Datos procesados info actualizada: {session['processed_data_info']}")
                        else: flash(f"Error en preprocesamiento: {msg}", 'error'); session.pop('processed_data_info', None)
                    except Exception as e_proc_call: print(f"ERROR llamando/procesando data_manager.preprocess_data: {e_proc_call}\n{traceback.format_exc()}"); flash(f"Error crítico durante el preprocesamiento: {e_proc_call}", "danger"); session.pop('processed_data_info', None)
                else: flash('Error: No hay datos cargados válidos para preprocesar. Intenta cargar el archivo de nuevo.', 'warning'); session.pop('processed_data_info', None)
            else: flash('Acción desconocida solicitada.', 'warning')
        except Exception as e: flash(f"Error crítico en gestión de datos: {e}", "error"); print(f"ERROR manage_data POST: {e}\n{traceback.format_exc()}"); session.pop('loaded_filepath', None); session.pop('processed_data_info', None)
        return redirect(url)
    # --- GET Request ---
    loaded_preview_headers = None; loaded_preview_data = None; processed_preview_headers = None; processed_preview_data = None
    p_info = session.get('processed_data_info'); l_path = session.get('loaded_filepath'); l_fname = os.path.basename(l_path) if l_path and os.path.exists(l_path) else None
    try:
        if l_fname:
            df_loaded = data_manager.get_loaded_data()
            if df_loaded is not None and not df_loaded.empty:
                df_loaded_head = df_loaded.head(10); loaded_preview_headers = df_loaded_head.columns.tolist(); loaded_preview_data = [[item if pd.notna(item) else '' for item in row] for row in df_loaded_head.values.tolist()]
        if p_info:
            df_processed = data_manager.get_processed_data()
            if df_processed is not None and not df_processed.empty:
                df_processed_head = df_processed.head(10); processed_preview_headers = df_processed_head.columns.tolist(); processed_preview_data = [[item if pd.notna(item) else '' for item in row] for row in df_processed_head.values.tolist()]
    except Exception as e: print(f"ERROR manage_data GET (preparando previews): {e}\n{traceback.format_exc()}"); flash("Error al preparar vistas previas de datos.", "error"); loaded_preview_headers, loaded_preview_data, processed_preview_headers, processed_preview_data = None, None, None, None
    return render_template('data_management.html', loaded_filename=l_fname, processed_info=p_info, loaded_preview_headers=loaded_preview_headers, loaded_preview_data=loaded_preview_data, processed_preview_headers=processed_preview_headers, processed_preview_data=processed_preview_data)

@app.route('/simulate', methods=['GET', 'POST'])
@login_required
def simulate():
    if request.method == 'POST':
        try:
            dur = int(request.form.get('duration', 60)); intensity = int(request.form.get('intensity', 5)); attacks_raw = request.form.getlist('attacks') if 'attacks' in request.form else []; attacks = [a.strip() for a in attacks_raw if isinstance(a, str) and a.strip()] or ['Generic Attack']
            if dur <= 0: raise ValueError("Duración debe ser > 0.")
            if not (1 <= intensity <= 10): raise ValueError("Intensidad debe estar entre 1-10.")
            cfg = {"duration": dur, "intensity": intensity, "attacks": attacks}; print(f"INFO: Solicitud simulación: {cfg}")
            df = simulator.run_simulation(cfg)
            if df is not None and not df.empty:
                sim_id = str(uuid.uuid4()); fname = f"sim_data_{sim_id}.pkl"; fpath = os.path.join(app.config['TEMP_SIM_FOLDER'], fname)
                try:
                    df.to_pickle(fpath); print(f"INFO: Datos de simulación guardados en: {fpath}")
                    session['simulation_info'] = {'rows_generated': len(df), 'config': cfg, 'timestamp': datetime.datetime.now().isoformat(timespec='seconds'), 'filepath': fpath}
                    simulator.add_to_history(session['simulation_info']); flash(f'Simulación completada. Generados {len(df)} registros.', 'success')
                except Exception as e_save: flash(f"Error al guardar archivo de simulación: {e_save}", "error"); print(f"ERROR guardando pickle de simulación: {e_save}\n{traceback.format_exc()}"); session.pop('simulation_info', None)
            else: flash('La simulación no generó datos válidos.', 'warning'); session.pop('simulation_info', None)
        except ValueError as ve: flash(f'Entrada inválida para la simulación: {ve}', 'error')
        except Exception as e: flash(f'Error inesperado durante la simulación: {e}', 'error'); print(f"ERROR simulate POST: {e}\n{traceback.format_exc()}"); session.pop('simulation_info', None)
        return redirect(url_for('simulate'))
    # --- GET Request ---
    print("DEBUG: Procesando GET /simulate"); sim_info = None; history = []; preview_headers = None; preview_data = None
    try:
        sim_info = session.get('simulation_info'); history = simulator.get_history()
        if sim_info and sim_info.get('filepath') and os.path.exists(sim_info['filepath']):
            try:
                df_preview = pd.read_pickle(sim_info['filepath']).head(10)
                if not df_preview.empty: preview_headers = df_preview.columns.tolist(); preview_data = [row.tolist() for _, row in df_preview.iterrows()]
            except Exception as e_load: print(f"WARN: No se pudo cargar/procesar el archivo pickle de simulación: {e_load}"); flash("No se pudo cargar la vista previa de la última simulación.", "warning")
    except Exception as e_get_prep: print(f"ERROR preparando datos para simulate GET: {e_get_prep}\n{traceback.format_exc()}"); flash("Error al cargar datos del simulador.", "error"); sim_info, history, preview_data, preview_headers = None, [], None, None
    return render_template('simulator.html', simulation_history=history, last_simulation_info=sim_info, preview_headers=preview_headers, preview_data=preview_data)

# (Tu código existente para /detect, /download_plot, /mark_alert_reviewed, /download_last_detection_csv)
@app.route('/detect', methods=['GET', 'POST'])
@login_required
def detect():
    print(f"DEBUG: /detect {request.method}")
    history = alert_manager.get_detection_history()
    session_res = session.get('last_detection_results')
    model_metrics = None; evaluation_report_data = None; evaluation_cm_plot_url = None; evaluation_cm_filename = None
    detection_preview_headers = None; detection_preview_data = None; detection_cm_plot_url = None; detection_cm_filename = None
    active_alerts = []; has_proc = False; has_sim = False
    if request.method == 'POST':
        print("DEBUG: POST /detect"); df = None; src_info = "N/A"; rows_count = 0
        try:
            ds = request.form.get('datasource'); print(f"DEBUG: Fuente seleccionada: {ds}")
            if ds == 'processed':
                df_proc = data_manager.get_processed_data()
                if df_proc is not None and not df_proc.empty: df = df_proc.copy(); src_info = "Datos Preprocesados Cargados"; rows_count = len(df); print(f"INFO: Usando {src_info} ({rows_count} filas)")
                else: flash("No hay datos preprocesados disponibles.", "warning"); return redirect(url_for('detect'))
            elif ds == 'simulation':
                sim = session.get('simulation_info')
                if sim and sim.get('filepath') and os.path.exists(sim['filepath']):
                    try:
                        print(f"INFO: Cargando datos desde simulación: {sim['filepath']}"); df_sim = pd.read_pickle(sim['filepath'])
                        if df_sim is not None and not df_sim.empty:
                            print("INFO: Preprocesando datos de simulación..."); df_processed_sim_result, preproc_msg = data_manager.preprocess_data(df_sim.copy())
                            if df_processed_sim_result is not None: df = df_processed_sim_result; src_info = f"Última Simulación ({os.path.basename(sim['filepath'])})"; rows_count = len(df); print(f"INFO: Usando {src_info} preprocesados ({rows_count} filas)")
                            else: raise RuntimeError(f"Falló preprocesamiento de simulación: {preproc_msg}")
                        else: raise FileNotFoundError("Archivo de simulación vacío.")
                    except Exception as e_ld_sim: print(f"ERROR al cargar o preprocesar simulación: {e_ld_sim}\n{traceback.format_exc()}"); flash(f"Error al cargar/preprocesar simulación: {e_ld_sim}", "danger"); return redirect(url_for('detect'))
                else: flash("No hay datos de simulación disponibles.", "warning"); return redirect(url_for('detect'))
            else: flash("Fuente de datos inválida.", "danger"); return redirect(url_for('detect'))
            if df is not None and not df.empty:
                final_output = None
                try: print("INFO: Llamando detector.run_detection()"); final_output = detector.run_detection(df); print("INFO: run_detection completado.")
                except Exception as e_det: print(f"ERROR durante detector.run_detection: {e_det}\n{traceback.format_exc()}"); flash(f"Error crítico durante la detección: {e_det}", "danger"); final_output = None
                if final_output is not None and isinstance(final_output, dict) and 'data' in final_output:
                    df_res = final_output.get('data')
                    if df_res is not None and not df_res.empty:
                        print("DEBUG: Procesando resultados post-detección...")
                        try:
                            current_threshold = detector.prediction_threshold if hasattr(detector, 'prediction_threshold') else system_config.get('glm_threshold')
                            results_for_session = {'ts': datetime.datetime.now().isoformat(timespec='seconds'), 'src': src_info, 'rows': rows_count, 'thr': current_threshold, 'metrics': final_output.get('metrics', {}), 'summary': final_output.get('detection_summary', {})}
                            prev_cols = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'label', 'prediction_label', 'prediction_proba']; avail = [c for c in prev_cols if c in df_res.columns]
                            df_prev = df_res[avail].head(10) if avail else df_res.head(10)
                            if 'prediction_proba' in df_prev.columns: df_prev['prediction_proba'] = df_prev['prediction_proba'].map('{:.4f}'.format)
                            results_for_session['head'] = df_prev.to_dict('records'); session['last_detection_results'] = results_for_session; print("DEBUG: Resultados guardados en sesión.")
                            hist_entry = results_for_session.copy(); hist_entry.pop('head', None); alert_manager.add_detection_to_history(hist_entry); print("INFO: Resumen añadido al historial persistente.")
                            if 'prediction_label' in df_res.columns:
                                n_alerts, _ = alert_manager.generate_alerts(df_res); print(f"INFO: {n_alerts} nuevas alertas generadas y guardadas en BD.")
                                if n_alerts > 0: flash(f"{n_alerts} nuevas alertas generadas.", "info")
                            else: print("WARN: Falta 'prediction_label' para generar alertas."); flash("Resultados generados, pero no se pudo generar alertas.", "warning")
                            print("SUCCESS: Post-detección OK."); flash("Detección completada con éxito.", "success")
                        except Exception as e_post: print(f"ERROR procesando resultados post-detección: {e_post}\n{traceback.format_exc()}"); flash(f"Error al procesar resultados o generar alertas: {e_post}", "danger")
                    else: print("WARN: DataFrame de resultados de detección vacío."); flash("La detección se ejecutó pero no produjo resultados.", "warning")
                else: print("WARN: La función de detección no devolvió resultados válidos."); flash("La detección no produjo resultados válidos o falló internamente.", "warning")
            else: print("ERROR: No había DataFrame válido para iniciar la detección."); flash("Error interno: No se pudieron preparar los datos para la detección.", "danger")
        except Exception as e_gen_post: print(f"ERROR general en POST /detect: {e_gen_post}\n{traceback.format_exc()}"); flash(f"Error interno grave durante la solicitud de detección: {e_gen_post}", "danger")
        return redirect(url_for('detect'))
    # --- GET Request ---
    try:
        print("DEBUG: Procesando GET /detect")
        eval_metrics = detector.evaluate_on_test_set() if hasattr(detector, 'evaluate_on_test_set') else None
        if eval_metrics and isinstance(eval_metrics, dict) and eval_metrics.get('accuracy') is not None:
            model_metrics = eval_metrics; print(f"DEBUG: Métricas de evaluación general obtenidas (Accuracy: {model_metrics.get('accuracy')}).")
            if model_metrics.get('confusion_matrix') is not None:
                print("DEBUG: Generando plot CM de evaluación GENERAL...");
                try:
                    evaluation_cm_plot_url, evaluation_cm_filename = generate_plot_base64_and_save(plot_confusion_matrix_func, model_metrics['confusion_matrix'], classes=model_metrics.get('classes'), title='Matriz Confusion (Evaluacion General Modelo)', save_plot=True, save_dir=app.config['SAVED_PLOTS_FOLDER'])
                    if evaluation_cm_plot_url: print(f"DEBUG: Plot CM eval generado (Archivo: {evaluation_cm_filename}).")
                except Exception as e_cm_gen: print(f"ERROR generando/guardando plot CM eval: {e_cm_gen}"); evaluation_cm_plot_url, evaluation_cm_filename = None, None
            report_dict = model_metrics.get('report');
            if report_dict and isinstance(report_dict, dict): evaluation_report_data = report_dict; print("DEBUG: Datos del reporte de evaluación listos para plantilla.")
            else: print("DEBUG: No hay datos de reporte de clasificación en métricas de evaluación general."); evaluation_report_data = None
        else: print("INFO: No hay métricas de evaluación general del modelo disponibles."); evaluation_report_data = None
        session_res = session.get('last_detection_results')
        if session_res:
            if isinstance(session_res.get('head'), list) and session_res['head']:
                try: head_records = session_res['head']; detection_preview_headers = list(head_records[0].keys()); detection_preview_data = [[row.get(header, '') for header in detection_preview_headers] for row in head_records]
                except Exception as e_head_prep: print(f"ERROR al preparar datos de vista previa: {e_head_prep}"); detection_preview_headers, detection_preview_data = None, None
            else: print("DEBUG: No hay datos de vista previa ('head') en última detección.")
            last_metrics = session_res.get('metrics')
            if last_metrics and isinstance(last_metrics, dict) and last_metrics.get('confusion_matrix') is not None:
                print("DEBUG: Generando plot CM de la ÚLTIMA DETECCIÓN...");
                try:
                    detection_cm_plot_url, detection_cm_filename = generate_plot_base64_and_save(plot_confusion_matrix_func, last_metrics['confusion_matrix'], classes=last_metrics.get('classes'), title='Matriz Confusion (Ultima Deteccion)', save_plot=True, save_dir=app.config['SAVED_PLOTS_FOLDER'])
                    if detection_cm_plot_url: print(f"DEBUG: Plot CM última detección generado (Archivo: {detection_cm_filename}).")
                except Exception as e_cm_det: print(f"ERROR generando/guardando plot CM última detección: {e_cm_det}"); detection_cm_plot_url, detection_cm_filename = None, None
            else: print("DEBUG: No hay datos de matriz de confusión en resultados de última detección.")
        else: print("DEBUG: No hay resultados de última detección en sesión.")
        sim = session.get('simulation_info'); has_sim = sim and sim.get('filepath') and os.path.exists(sim['filepath'])
        df_processed = data_manager.get_processed_data(); has_proc = df_processed is not None and not df_processed.empty
        print(f"DEBUG: Disponibilidad datos para formulario - Sim: {has_sim}, Proc: {has_proc}")
        print("DEBUG: Obteniendo alertas activas desde BD...");
        try: alerts = alert_manager.get_alerts(show_all=False); print(f"DEBUG: {len(alerts)} alertas activas obtenidas.")
        except Exception as e_al: print(f"ERROR obteniendo alertas activas: {e_al}"); flash("Error al cargar las alertas.", "error"); alerts = []
    except Exception as e_get: print(f"ERROR general en GET /detect: {e_get}\n{traceback.format_exc()}"); flash("Ocurrió un error interno al preparar la página.", "danger"); model_metrics, evaluation_report_data, evaluation_cm_plot_url, evaluation_cm_filename = None, None, None, None; detection_cm_plot_url, detection_cm_filename = None, None; detection_preview_headers, detection_preview_data = None, None; alerts = []; has_proc, has_sim = False, False
    print("DEBUG: Renderizando detection.html...")
    return render_template('detection.html', has_processed_data=has_proc, has_simulation_data=has_sim, current_model_metrics=model_metrics, evaluation_report_data=evaluation_report_data, evaluation_cm_plot_url=evaluation_cm_plot_url, evaluation_cm_filename=evaluation_cm_filename, last_detection_results=session_res, detection_preview_headers=detection_preview_headers, detection_preview_data=detection_preview_data, detection_cm_plot_url=detection_cm_plot_url, detection_cm_filename=detection_cm_filename, detection_history=history, active_alerts=alerts)

@app.route('/download_plot/<path:filename>')
@login_required
def download_plot(filename):
    print(f"DEBUG: Solicitud descarga gráfico: {filename}"); safe_filename = secure_filename(filename)
    if not safe_filename or '..' in safe_filename or safe_filename.startswith(('/', '\\')): print(f"WARN: Intento de descarga de archivo inválido/peligroso: {filename}"); flash("Nombre de archivo inválido.", "danger"); return redirect(url_for('dashboard'))
    plot_dir = app.config.get('SAVED_PLOTS_FOLDER', os.path.join(BASE_DIR, 'saved_plots')); filepath = os.path.join(plot_dir, safe_filename); print(f"DEBUG: Buscando gráfico en ruta absoluta: {filepath}")
    if os.path.exists(filepath) and os.path.commonpath([plot_dir]) == os.path.commonpath([plot_dir, filepath]):
         try: print(f"INFO: Enviando archivo de gráfico: {filepath}"); return send_file(filepath, as_attachment=True)
         except Exception as e: print(f"ERROR al enviar archivo de gráfico {filepath}: {e}"); flash("Error al intentar descargar el gráfico.", "error"); return redirect(url_for('detect'))
    else: print(f"WARN: Archivo de gráfico no encontrado o fuera del directorio permitido: {filepath}"); flash("El archivo del gráfico solicitado no se encontró.", "warning"); return redirect(url_for('detect'))

@app.route('/mark_alert_reviewed/<int:alert_id>', methods=['POST'])
@login_required
def mark_alert_reviewed(alert_id):
    print(f"DEBUG: POST /mark_alert_reviewed/{alert_id}"); origin_page = request.form.get('origin', 'detect'); redirect_url = url_for(origin_page); print(f"DEBUG: Origen para redirigir: {origin_page} -> {redirect_url}")
    try:
        success = alert_manager.mark_alert_reviewed(alert_id)
        if success: msg = f"Alerta ID {alert_id} marcada como revisada."; flash(msg, 'success'); print(f"INFO: Alerta {alert_id} marcada por {current_user.username}.")
        else: msg = f"No se pudo marcar la alerta {alert_id} como revisada (no existe o error BD)."; flash(msg, 'warning'); print(f"WARN: No se marcó alerta {alert_id}.")
    except Exception as e: msg = f"Error al intentar marcar alerta {alert_id}: {e}"; flash(msg, "error"); print(f"ERROR marcar alerta {alert_id}: {e}\n{traceback.format_exc()}")
    return redirect(redirect_url)

@app.route('/report/last_detection_csv')
@login_required
def download_last_detection_csv():
    print("DEBUG: GET /report/last_detection_csv"); results = session.get('last_detection_results')
    if not results: flash("No hay resultados de la última detección disponibles.", "warning"); return redirect(url_for('detect'))
    try:
        csv_content = generate_last_detection_csv(results)
        if csv_content is None: raise ValueError("La función de generación de CSV devolvió None.")
        response = make_response(csv_content); ts_actual = datetime.datetime.now().strftime('%Y%m%d_%H%M%S'); filename = f"reporte_deteccion_{ts_actual}.csv"
        response.headers["Content-Disposition"] = f"attachment; filename=\"{filename}\""; response.headers["Content-Type"] = "text/csv; charset=utf-8"; print(f"INFO: Reporte CSV generado para descarga: {filename}"); return response
    except Exception as e: print(f"ERROR generando/enviando reporte CSV: {e}\n{traceback.format_exc()}"); flash(f"Error interno al generar el reporte CSV: {e}", "error"); return redirect(url_for('detect'))


# --- RUTAS ADMIN ---

# >>>>>>>> INICIO SECCIÓN MODIFICADA PARA SPRINT 5 <<<<<<<<<

# --- Función auxiliar para obtener la lista de modelos ---
def get_saved_models_list():
    """Obtiene la lista de archivos de modelos guardados desde el detector."""
    if hasattr(detector, 'get_saved_model_list'):
        try:
            return detector.get_saved_model_list()
        except Exception as e:
            print(f"ERROR [App]: Llamando detector.get_saved_model_list(): {e}")
            return [] # Devuelve lista vacía en caso de error en el detector
    else:
        print("WARN [App]: detector no tiene método get_saved_model_list().")
        return [] # Devuelve lista vacía si el método no existe

# --- Modificar la ruta /admin (GET) para pasar la lista de modelos ---
@app.route('/admin')
@login_required
@admin_required
def admin_landing():
    print("DEBUG: GET /admin")
    saved_models = [] # Inicializar lista por defecto
    try:
        # --- Tu código existente para cargar config, logs etc. ---
        current_threshold = detector.prediction_threshold if hasattr(detector, 'prediction_threshold') else system_config.get('glm_threshold', 0.7)
        alert_config = alert_manager.config if hasattr(alert_manager, 'config') else {}
        current_severity = alert_config.get('severity_threshold', 'Media')
        current_notify_email = alert_config.get('notify_email', False)
        severity_levels = alert_manager.get_severity_levels() if hasattr(alert_manager, 'get_severity_levels') else ['Baja', 'Media', 'Alta', 'Crítica']
        # Manejo de logs más robusto
        logs = []
        if hasattr(admin_manager, 'get_system_logs'):
            try:
                logs = admin_manager.get_system_logs()
            except Exception as e_log:
                print(f"ERROR [App]: Obteniendo logs desde admin_manager: {e_log}")
                logs = ["Error al cargar logs."]
        else:
             logs = ["Funcionalidad de logs no implementada."]
        # -------------------------------------------------------

        # Obtener la lista de modelos guardados llamando a la función auxiliar
        saved_models = get_saved_models_list() # <<< LLAMADA A LA FUNCIÓN AUXILIAR
        print(f"DEBUG [App]: Modelos guardados encontrados para plantilla: {saved_models}")

    except Exception as e:
        print(f"ERROR cargando datos para /admin: {e}\n{traceback.format_exc()}")
        flash("Error al cargar la página de administración.", "error")
        # Resetear variables en caso de error
        current_threshold, current_severity, current_notify_email = 0.7, 'Media', False
        severity_levels = ['Baja', 'Media', 'Alta', 'Crítica']
        logs = ["Error al cargar logs."]
        saved_models = [] # Resetear lista de modelos también

    # Pasar la lista de modelos a la plantilla
    return render_template('admin.html',
                           glm_threshold=current_threshold,
                           alert_severity_threshold=current_severity,
                           notify_email=current_notify_email,
                           alert_severity_levels=severity_levels,
                           system_logs=logs,
                           saved_models_list=saved_models) # <<< PASAR LA LISTA AL TEMPLATE


# --- Modificar la ruta /admin/action (POST) para incluir las nuevas acciones ---
@app.route('/admin/action', methods=['POST'])
@login_required
@admin_required
def admin_actions():
    action = request.form.get('action')
    print(f"INFO [App]: POST /admin/action - Acción recibida: {action}")
    global system_config # Necesario para modificar config global

    try:
        # --- ACCIONES EXISTENTES (Se mantienen sin cambios) ---
        if action == 'update_threshold':
            # (Tu código existente, verificado que funciona)
            try:
                 thr_str = request.form.get('glm_threshold_admin')
                 if thr_str is None: raise ValueError("Falta umbral GLM en form.")
                 thr = float(thr_str)
                 if 0.0 <= thr <= 1.0:
                     if hasattr(detector, 'prediction_threshold'): detector.prediction_threshold = thr
                     system_config['glm_threshold'] = thr
                     if hasattr(admin_manager, 'save_system_config'): admin_manager.save_system_config(system_config)
                     flash(f"Umbral GLM actualizado a {thr:.2f}.", "success"); print(f"INFO [App]: Umbral GLM -> {thr} actualizado por admin {current_user.username}.")
                 else: flash("Umbral GLM debe estar entre 0.0 y 1.0.", "warning")
            except ValueError: flash("Valor de umbral GLM inválido.", 'error')
            except Exception as e_thr: flash(f"Error al actualizar umbral GLM: {e_thr}", "danger"); print(f"ERROR [App]: update_threshold action: {e_thr}\n{traceback.format_exc()}")

        elif action == 'update_alert_config':
             # (Tu código existente, verificado que funciona)
             sev = request.form.get('alert_severity_threshold_admin')
             notify = request.form.get('notify_email_admin') == 'on'
             if hasattr(alert_manager, 'update_config'):
                  if alert_manager.update_config(severity_threshold=sev, notify_email=notify):
                       flash("Configuración de alertas actualizada.", "success"); print(f"INFO [App]: Config alertas (Sev:{sev}, Email:{notify}) actualizada por admin {current_user.username}.")
                  else: flash("Error al actualizar la configuración de alertas.", "warning")
             else: flash("Error interno: Gestor de alertas no actualizable.", "danger"); print("ERROR [App]: alert_manager no tiene método update_config.")

        elif action == 'retrain': # REENTRENAMIENTO COMPLETO
             # (Tu código existente, verificado que funciona)
             print("INFO [App]: Solicitud de reentrenamiento COMPLETO recibida.")
             df_proc = data_manager.get_processed_data()
             if df_proc is not None and not df_proc.empty:
                 print(f"INFO [App]: Reentrenando (completo) con {len(df_proc)} filas.")
                 try:
                     success, msg = detector.train_and_save_model(df_proc.copy()) # Pasar copia
                     flash(msg, 'success' if success else 'danger')
                     if success: print("INFO [App]: Reentrenamiento completo y guardado de modelo activo OK.")
                 except Exception as e_tr: flash(f"Error durante el reentrenamiento completo: {e_tr}", "danger"); print(f"ERROR [App]: en detector.train_and_save_model (completo): {e_tr}\n{traceback.format_exc()}")
             else: flash("No hay datos preprocesados disponibles para reentrenamiento completo.", 'warning'); print("WARN [App]: Reentrenamiento completo sin datos preprocesados.")


        # --- NUEVA ACCIÓN: Añadir Datos y Reentrenar (TR-17) ---
        elif action == 'add_data_and_retrain':
            print("INFO [App]: Solicitud 'Añadir Datos y Reentrenar' recibida.")
            if 'new_data_file' not in request.files:
                flash('No se seleccionó ningún archivo para añadir datos.', 'warning')
                return redirect(url_for('admin_landing')) # Redirigir a admin

            file = request.files['new_data_file']
            if file.filename == '':
                flash('No se seleccionó ningún archivo.', 'warning')
                return redirect(url_for('admin_landing'))

            if file and allowed_file(file.filename): # Usa tu función allowed_file
                new_filepath = None # Definir fuera del try para usar en finally
                try:
                    # 1. Carga datos existentes (ya preprocesados)
                    df_existing_processed = data_manager.get_processed_data() # Obtener copia desde memoria/archivo
                    if df_existing_processed is None or df_existing_processed.empty:
                        flash('Error: No hay datos procesados existentes para añadir. Realiza un preprocesamiento inicial primero.', 'danger')
                        return redirect(url_for('admin_landing'))

                    # 2. Guarda y carga el archivo nuevo
                    new_filename_secure = secure_filename(file.filename)
                    # Guardar en carpeta de uploads temporalmente
                    new_filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_new_{new_filename_secure}")
                    file.save(new_filepath)
                    # Leer el archivo nuevo que acabamos de guardar
                    df_new_raw, msg_load_new = data_manager.load_csv_data(new_filepath) # Usar load_csv_data para robustez
                    if not df_new_raw: # Si falló la carga del nuevo archivo
                         flash(msg_load_new, 'danger')
                         if os.path.exists(new_filepath): os.remove(new_filepath)
                         return redirect(url_for('admin_landing'))
                    print(f"INFO [App]: Archivo nuevo cargado temporalmente: {new_filename_secure} ({len(data_manager.get_loaded_data())} filas raw)")

                    # 3. Preprocesa los datos NUEVOS usando la misma lógica
                    print("INFO [App]: Preprocesando datos nuevos...")
                    # Llamar a preprocess_data con los datos raw recién cargados en DataManager
                    df_new_processed, preproc_msg = data_manager.preprocess_data(data_manager.get_loaded_data()) # Usar el raw cargado

                    if df_new_processed is None: # Falló el preprocesamiento del nuevo archivo
                        flash(f"Error al preprocesar el archivo nuevo '{new_filename_secure}': {preproc_msg}", 'danger')
                        if os.path.exists(new_filepath): os.remove(new_filepath) # Limpiar
                        return redirect(url_for('admin_landing'))

                    print(f"INFO [App]: Datos nuevos preprocesados: {df_new_processed.shape}")

                    # 4. Verifica columnas antes de combinar
                    if set(df_existing_processed.columns) != set(df_new_processed.columns):
                        flash(f'Error: Las columnas preprocesadas del archivo nuevo ({list(df_new_processed.columns)}) no coinciden con las existentes ({list(df_existing_processed.columns)}). Revisa el formato del archivo CSV.', 'danger')
                        if os.path.exists(new_filepath): os.remove(new_filepath) # Limpiar
                        return redirect(url_for('admin_landing'))
                     # Reordenar por si acaso para asegurar el orden
                    df_new_processed = df_new_processed[df_existing_processed.columns]

                    # 5. Combina los DataFrames (existente procesado + nuevo procesado)
                    df_combined = pd.concat([df_existing_processed, df_new_processed], ignore_index=True)
                    # Opcional: Eliminar duplicados DESPUÉS de combinar
                    rows_before_dedup = len(df_combined)
                    df_combined.drop_duplicates(inplace=True)
                    print(f"INFO [App]: Datos combinados ({rows_before_dedup} -> {len(df_combined)} filas tras drop_duplicates) listos para reentrenamiento.")


                    # 6. Reentrena el modelo ACTIVO con los datos combinados
                    print("INFO [App]: Reentrenando modelo activo con datos combinados...")
                    # Pasar copia del combinado a la función de entrenamiento
                    success_train, msg_train = detector.train_and_save_model(df_combined.copy())

                    if success_train:
                        # 7. SI el entrenamiento fue exitoso, AHORA actualiza DataManager con el combinado
                        print("INFO [App]: Actualizando DataManager con datos combinados...")
                        # Llama al método que AÑADISTE a DataManager
                        if hasattr(data_manager, 'update_processed_data'):
                            success_update, msg_update = data_manager.update_processed_data(df_combined) # Pasar el combinado final
                            if success_update:
                                flash(f"Modelo reentrenado con datos añadidos ({len(df_new_processed)} filas procesadas nuevas). {msg_train}", 'success')
                            else:
                                flash(f"¡Advertencia! Modelo reentrenado, pero falló al actualizar/guardar la base de datos procesados: {msg_update}. Los próximos reentrenamientos incrementales pueden no incluir estos datos.", 'warning')
                        else:
                             flash("¡Advertencia! Modelo reentrenado, pero DataManager no tiene el método 'update_processed_data' para persistir el estado combinado.", 'warning')
                             print("ERROR [App]: Falta data_manager.update_processed_data")
                    else:
                        # Falló el entrenamiento
                        flash(f"Falló el reentrenamiento con datos combinados: {msg_train}", 'danger')

                except FileNotFoundError as fnf:
                     flash(f"Error de archivo: {fnf}. ¿Existe el archivo de datos procesados existente?", 'danger')
                     print(f"ERROR [App] FileNotFoundError en add_data_and_retrain: {fnf}\n{traceback.format_exc()}")
                except ValueError as ve:
                     flash(f"Error en los datos durante el proceso: {ve}", 'danger')
                     print(f"ERROR [App] ValueError en add_data_and_retrain: {ve}\n{traceback.format_exc()}")
                except Exception as e_inc:
                    flash(f'Error durante el reentrenamiento incremental: {e_inc}', 'danger')
                    print(f"ERROR [App]: en add_data_and_retrain: {e_inc}\n{traceback.format_exc()}")
                finally:
                     # Asegurarse de borrar el archivo temporal subido
                     if new_filepath and os.path.exists(new_filepath):
                         try:
                             os.remove(new_filepath)
                             print(f"INFO [App]: Archivo temporal {new_filepath} eliminado.")
                         except Exception as e_del_temp:
                             print(f"WARN [App]: No se pudo eliminar archivo temporal {new_filepath}: {e_del_temp}")
            else:
                flash('Tipo de archivo no permitido. Solo CSV.', 'error')


        # --- NUEVAS ACCIONES: Guardar, Cargar, Eliminar Modelo (TR-18) ---
        elif action == 'save_model':
            save_name = request.form.get('save_name')
            if not save_name:
                 flash("Se requiere un nombre para guardar el modelo.", 'warning')
            # Llama al método que AÑADISTE a ThreatDetector
            elif hasattr(detector, 'save_active_model_as'):
                success, msg = detector.save_active_model_as(save_name)
                flash(msg, 'success' if success else 'danger')
                if success: print(f"INFO [App]: Admin {current_user.username} guardó modelo como '{save_name}'.")
            else:
                flash("Funcionalidad 'save_active_model_as' no implementada en Detector.", "danger")
                print("ERROR [App]: detector no tiene método save_active_model_as.")

        elif action == 'load_model':
            filename_to_load = request.form.get('model_filename_to_load')
            if not filename_to_load:
                 flash("Debes seleccionar un modelo para cargar.", 'warning')
            # Llama al método que AÑADISTE a ThreatDetector
            elif hasattr(detector, 'load_model_as_active'):
                success, msg = detector.load_model_as_active(filename_to_load)
                flash(msg, 'success' if success else 'danger')
                if success: print(f"INFO [App]: Admin {current_user.username} cargó modelo '{filename_to_load}' como activo.")
            else:
                 flash("Funcionalidad 'load_model_as_active' no implementada en Detector.", "danger")
                 print("ERROR [App]: detector no tiene método load_model_as_active.")

        elif action == 'delete_model':
            filename_to_delete = request.form.get('model_filename_to_delete')
            if not filename_to_delete:
                 flash("Debes seleccionar un modelo para eliminar.", 'warning')
            # Llama al método que AÑADISTE a ThreatDetector
            elif hasattr(detector, 'delete_saved_model'):
                 success, msg = detector.delete_saved_model(filename_to_delete)
                 flash(msg, 'success' if success else 'danger')
                 if success: print(f"INFO [App]: Admin {current_user.username} eliminó modelo guardado '{filename_to_delete}'.")
            else:
                  flash("Funcionalidad 'delete_saved_model' no implementada en Detector.", "danger")
                  print("ERROR [App]: detector no tiene método delete_saved_model.")


        # --- ACCIONES EXISTENTES (delete_all_alerts) ---
        elif action == 'delete_all_alerts':
             # (Tu código existente, verificado que funciona)
             print("INFO [App]: Admin solicitó borrar todas las alertas.")
             try:
                 # Asume que alert_manager tiene este método
                 success, msg = alert_manager.delete_all_alerts()
                 flash(msg, 'success' if success else 'error')
                 if success: print("INFO [App]: Todas las alertas borradas.")
             except Exception as e_del:
                 flash(f"Error al borrar alertas: {e_del}", "danger")
                 print(f"ERROR [App]: delete_all_alerts: {e_del}\n{traceback.format_exc()}")
        else:
            flash(f"Acción de administrador desconocida: '{action}'.", 'warning')
            print(f"WARN [App]: Acción admin desconocida recibida: {action}")

    except Exception as e:
        # Captura errores generales en el manejo de la acción
        flash(f"Error interno al procesar la acción del administrador: {e}", "error")
        print(f"ERROR [App]: procesando admin POST action '{action}': {e}\n{traceback.format_exc()}")

    # Redirigir de vuelta a la página de admin después de CUALQUIER acción POST
    return redirect(url_for('admin_landing'))

# >>>>>>>> FIN SECCIÓN MODIFICADA PARA SPRINT 5 <<<<<<<<<


# --- RUTAS GESTIÓN USUARIOS (Admin) ---
# (Tu código existente para /admin/users, /admin/users/new, /admin/users/<id>/edit, /admin/users/<id>/delete)
@app.route('/admin/users')
@login_required
@admin_required
def list_users():
    print("DEBUG: GET /admin/users"); users = []; delete_form = DeleteUserForm()
    try: users = User.query.order_by(User.username).all()
    except Exception as e: print(f"Err obtener users: {e}"); flash("Error cargar users.", "error")
    return render_template('users_list.html', users=users, delete_form=delete_form)

@app.route('/admin/users/new', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    print(f"DEBUG: /admin/users/new {request.method}"); form = UserAdminForm()
    if form.validate_on_submit():
        try:
            user = User(username=form.username.data, email=form.email.data, is_admin=form.is_admin.data)
            if form.password.data: user.set_password(form.password.data); db.session.add(user); db.session.commit(); flash(f'Usuario "{user.username}" creado exitosamente.', 'success'); print(f"INFO: Admin {current_user.username} creó usuario {user.username}."); return redirect(url_for('list_users'))
            else: flash("La contraseña es obligatoria al crear un nuevo usuario.", "danger")
        except ValidationError as ve: flash(f"Error de validación: {ve}", 'danger'); print(f"WARN: ValidErr create user: {ve}")
        except Exception as e: db.session.rollback(); flash(f'Error al crear usuario: {e}', 'danger'); print(f"ERR crear usuario: {e}")
        return render_template('user_form.html', title='Crear Nuevo Usuario', form=form, is_new=True)
    return render_template('user_form.html', title='Crear Nuevo Usuario', form=form, is_new=True)

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    print(f"DEBUG: /admin/users/{user_id}/edit {request.method}"); user = User.query.get_or_404(user_id); form = UserAdminForm(original_username=user.username, original_email=user.email)
    if form.validate_on_submit():
        try:
            user.username=form.username.data; user.email=form.email.data; user.is_admin=form.is_admin.data; password_changed = False
            if form.password.data: print(f"INFO: Actualizando contraseña para user {user.username}"); user.set_password(form.password.data); password_changed = True
            db.session.commit(); flash(f'Usuario "{user.username}" actualizado correctamente.' + (' (Contraseña cambiada)' if password_changed else ''), 'success'); print(f"INFO: Admin {current_user.username} editó usuario {user.username}. Contraseña cambiada: {password_changed}."); return redirect(url_for('list_users'))
        except ValidationError as ve: flash(f"Error de validación: {ve}", 'danger'); print(f"WARN: ValidErr edit user {user_id}: {ve}")
        except Exception as e: db.session.rollback(); flash(f'Error al actualizar usuario: {e}', 'danger'); print(f"ERR edit user {user_id}: {e}")
        form.username.data = user.username; form.email.data = user.email; form.is_admin.data = user.is_admin
        return render_template('user_form.html', title=f'Editar Usuario: {user.username}', form=form, user=user, is_new=False)
    elif request.method == 'GET': form.username.data = user.username; form.email.data = user.email; form.is_admin.data = user.is_admin
    return render_template('user_form.html', title=f'Editar Usuario: {user.username}', form=form, user=user, is_new=False)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    print(f"DEBUG: POST /admin/users/{user_id}/delete"); user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.id == current_user.id: flash("No puedes eliminar tu propia cuenta de administrador.", "danger"); return redirect(url_for('list_users'))
    form = DeleteUserForm()
    if form.validate_on_submit():
        try: username_deleted = user_to_delete.username; db.session.delete(user_to_delete); db.session.commit(); flash(f'Usuario "{username_deleted}" eliminado exitosamente.', 'success'); print(f"INFO: Admin {current_user.username} eliminó usuario {username_deleted} (ID: {user_id}).")
        except Exception as e: db.session.rollback(); flash(f'Error al eliminar el usuario "{user_to_delete.username}": {e}', 'danger'); print(f"ERROR al eliminar usuario {user_id}: {e}")
    else: flash("Error en la solicitud de borrado. Intenta de nuevo.", "danger"); print(f"WARN: Falló validación de formulario al borrar user {user_id} (posiblemente CSRF).")
    return redirect(url_for('list_users'))


# --- Ruta Settings ---
# (Tu código existente para /settings)
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    print(f"DEBUG: Accediendo a /settings con método {request.method}"); global system_config, detector, alert_manager
    if request.method == 'POST':
        print("DEBUG: Procesando POST /settings")
        try:
            thr_str = request.form.get('glm_threshold')
            if thr_str is not None:
                 try:
                     thr = float(thr_str)
                     if 0.0 <= thr <= 1.0:
                         if hasattr(detector, 'prediction_threshold'): detector.prediction_threshold = thr
                         system_config['glm_threshold'] = thr
                         if hasattr(admin_manager, 'save_system_config'): admin_manager.save_system_config(system_config)
                         flash(f"Umbral de detección actualizado a {thr:.2f}.", "success"); print(f"INFO: Umbral GLM -> {thr} actualizado por {current_user.username}.")
                     else: flash("Valor de umbral GLM fuera del rango (0.0 - 1.0).", "warning")
                 except ValueError: flash("Valor de umbral GLM inválido.", "warning")
            sev = request.form.get('severity_threshold'); email = request.form.get('notify_email') == 'on'
            if hasattr(alert_manager, 'update_config'):
                 current_config = alert_manager.config
                 if current_config.get('severity_threshold') != sev or current_config.get('notify_email') != email:
                      if alert_manager.update_config(severity_threshold=sev, notify_email=email): flash("Configuración de alertas actualizada.", "success"); print(f"INFO: Configuración alertas (Sev:{sev}, Email:{email}) por {current_user.username}.")
                      else: flash("Error al actualizar la configuración de alertas.", "warning")
            else: print("WARN: alert_manager no tiene método update_config.")
            return redirect(url_for('settings'))
        except Exception as e: print(f"ERROR procesando POST /settings: {e}\n{traceback.format_exc()}"); flash(f"Error interno al guardar la configuración: {e}", "danger")
    # --- GET Request ---
    try:
        print("DEBUG: Procesando GET /settings")
        current_threshold = detector.prediction_threshold if hasattr(detector, 'prediction_threshold') else system_config.get('glm_threshold', 0.7)
        current_severity = 'Media'; current_notify_email = False; severity_levels = ['Baja', 'Media', 'Alta', 'Crítica']
        if hasattr(alert_manager, 'config'): current_severity = alert_manager.config.get('severity_threshold', 'Media'); current_notify_email = alert_manager.config.get('notify_email', False)
        if hasattr(alert_manager, 'get_severity_levels'): severity_levels = alert_manager.get_severity_levels()
        print(f"DEBUG: GET /settings - Valores actuales: Thr={current_threshold}, Sev={current_severity}, Email={current_notify_email}")
        return render_template('settings.html', title='Configuración', glm_threshold=current_threshold, severity_threshold=current_severity, notify_email=current_notify_email, alert_severity_levels=severity_levels)
    except Exception as e: print(f"ERROR preparando GET /settings: {e}\n{traceback.format_exc()}"); flash("Error al cargar la página de configuración.", "danger"); return render_template('settings.html', title='Configuración', glm_threshold=0.7, severity_threshold='Media', notify_email=False, alert_severity_levels=['Baja', 'Media', 'Alta', 'Crítica'])


# --- Creación de Tablas y Ejecución ---
if __name__ == '__main__':
    with app.app_context():
        print("INFO: Verificando/Creando tablas de BD si no existen...")
        t_start = datetime.datetime.now()
        try:
            db.create_all()
            t_end = datetime.datetime.now(); print(f"INFO: db.create_all() completado en {(t_end - t_start).total_seconds():.2f} segundos.")
            if User.query.count() == 0:
                print("INFO: No existen usuarios. Creando usuario 'admin' inicial...")
                try:
                    admin_user = User(username='admin', email='admin@example.com', is_admin=True); admin_user.set_password('ChangeMe123!'); db.session.add(admin_user); db.session.commit()
                    print("INFO: Usuario 'admin' creado con contraseña 'ChangeMe123!'. ¡CAMBIARLA INMEDIATAMENTE!")
                except Exception as e_adm: db.session.rollback(); print(f"ERROR crítico al crear usuario admin inicial: {e_adm}")
        except Exception as e_db_init: print(f"FATAL ERROR al inicializar la base de datos con db.create_all(): {e_db_init}"); print("Verifica la configuración de conexión y que el servidor MySQL esté corriendo."); exit()
    print("INFO: Iniciando servidor Flask...")
    app.run(host='0.0.0.0', port=5000, debug=True) # ¡NO USAR debug=True EN PRODUCCIÓN!