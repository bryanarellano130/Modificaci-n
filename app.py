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
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TEMP_SIM_FOLDER'] = TEMP_SIM_FOLDER
app.config['SAVED_PLOTS_FOLDER'] = SAVED_PLOTS_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'csv'}
print(f"DEBUG: Carpetas configuradas: UPLOAD={app.config['UPLOAD_FOLDER']}, TEMP_SIM={app.config['TEMP_SIM_FOLDER']}, PLOTS={app.config['SAVED_PLOTS_FOLDER']}")

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

# --- Instancias Globales (Managers) ---
# Mover la carga de config a una función o después de inicializar managers si dependen de ella
# system_config = {'glm_threshold': 0.7} # Configuración global inicial - Cargar después

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

try:
    print("DEBUG: Inicializando Managers...")
    # Asegúrate que las clases Manager estén definidas correctamente en sus archivos
    data_manager = DataManager()
    simulator = ThreatSimulator()
    alert_manager = AlertManager()
    detector = ThreatDetector() # Asume que carga el modelo/scaler al inicializar
    # Pasar el detector al admin manager si es necesario
    admin_manager = AdminManager(detector_instance=detector)
    print("DEBUG: Managers inicializados.")
    # Cargar configuración del sistema DESPUÉS de inicializar managers si dependen de ella
    system_config = admin_manager.system_config # Asume que admin_manager carga la config
    print(f"DEBUG: Configuración del sistema cargada/inicializada: {system_config}")
except NameError as ne:
     print(f"FATAL ERROR: Parece que una clase Manager no está definida o importada: {ne}")
     exit()
except Exception as e:
    print(f"FATAL ERROR inicializando manager o cargando config: {e}\n{traceback.format_exc()}")
    exit()


# --- MODELO DE BASE DE DATOS (USUARIO) ---
print("DEBUG: Definiendo modelo User...")
class User(db.Model, UserMixin):
    __tablename__ = 'users' # Nombre explícito de la tabla
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # Aumentar longitud para hashes de bcrypt
    password_hash = db.Column(db.String(60), nullable=False) # bcrypt hashes son de 60 chars
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def set_password(self, password):
        try:
            password_bytes = password.encode('utf-8')
            # Generar salt y hashear
            salt = bcrypt.gensalt()
            self.password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8') # Guardar como string
        except Exception as e:
            print(f"Error al hashear la contraseña para {self.username}: {e}")
            # Considera lanzar una excepción o manejar el error apropiadamente
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
            # Esto puede ocurrir si el hash almacenado no es un hash bcrypt válido
            print(f"ERROR (ValueError) al verificar contraseña para usuario {self.id}: {ve}. Hash inválido?")
            return False
        except Exception as e:
            print(f"ERROR general al verificar contraseña para usuario {self.id}: {e}")
            return False # Seguridad por defecto: si hay error, no coincide

    def __repr__(self):
        return f'<User {self.username}>'
print("DEBUG: Modelo User definido.")

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    """ Carga un usuario dado su ID para Flask-Login. """
    print(f"DEBUG: load_user llamado para ID: {user_id}")
    try:
        # Usar db.session.get que es más eficiente para buscar por PK
        user = db.session.get(User, int(user_id))
        if user:
            print(f"DEBUG: Usuario {user.username} encontrado.")
        else:
            print(f"DEBUG: Usuario ID {user_id} no encontrado.")
        return user
    except ValueError:
        print(f"ERROR: ID de usuario inválido: {user_id}")
        return None
    except Exception as e:
        print(f"ERROR cargando usuario ID {user_id}: {e}")
        # Considera db.session.rollback() si la sesión está en mal estado
        return None


# --- FORMULARIOS (Flask-WTF) ---
print("DEBUG: Definiendo Formularios...")
# (Los formularios LoginForm, RegistrationForm, UserAdminForm, DeleteUserForm como los tenías antes)
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

    # Validadores personalizados para asegurar unicidad
    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Este nombre de usuario ya existe. Por favor, elige otro.')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Este email ya está registrado. Por favor, usa otro.')

print("DEBUG: Formularios Login/Registration definidos.")

class UserAdminForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Nueva Contraseña (dejar vacío para no cambiar)')
    is_admin = BooleanField('Es Administrador')
    submit = SubmitField('Guardar Usuario')

    # Guardar valores originales para validación de unicidad al editar
    def __init__(self, original_username=None, original_email=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email

    def validate_username(self, username):
        # Solo validar si el nombre de usuario cambió
        if username.data != self.original_username:
            if User.query.filter_by(username=username.data).first():
                raise ValidationError('Este nombre de usuario ya existe.')

    def validate_email(self, email):
        # Solo validar si el email cambió
        if email.data != self.original_email:
            if User.query.filter_by(email=email.data).first():
                raise ValidationError('Este email ya está registrado.')

class DeleteUserForm(FlaskForm):
    # Usado solo para protección CSRF en la acción de borrado
    submit = SubmitField('Eliminar Usuario')

print("DEBUG: Formularios Admin definidos.")

# --- Context Processor (inyecta variables globales a todas las plantillas) ---
@app.context_processor
def inject_global_vars():
    return {'current_year': datetime.datetime.now().year,
            'now': datetime.datetime.now}

# --- Filtro Jinja2 para Fechas (mejorado) ---
@app.template_filter('format_datetime')
def format_datetime_filter(value, format='%Y-%m-%d %H:%M:%S'):
    if not value:
        return "N/A"
    # Intentar convertir si es string ISO
    if isinstance(value, str):
        try:
            # Manejar posibles formatos ISO (con o sin microsegundos)
            if '.' in value:
                 dt = datetime.datetime.fromisoformat(value.split('.')[0])
            else:
                 dt = datetime.datetime.fromisoformat(value)
            return dt.strftime(format)
        except ValueError:
            # Intentar otros formatos comunes si falla ISO
            for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S'): # Añadir formatos si es necesario
                 try:
                     dt = datetime.datetime.strptime(value, fmt)
                     return dt.strftime(format)
                 except ValueError:
                     pass
            print(f"WARN: format_datetime no pudo parsear string: {value}")
            return value # Devolver original si falla todo
    # Si ya es datetime, formatearlo
    elif isinstance(value, datetime.datetime):
         try:
              return value.strftime(format)
         except Exception as e_fmt:
              print(f"WARN: format_datetime err formateando dt: {e_fmt}")
              return str(value) # Devolver string si falla formato
    else:
         # Si no es string ni datetime, intentar convertir a string
         print(f"WARN: format_datetime recibió tipo inesperado: {type(value)}")
         return str(value)

# --- Funciones de Reporte (Como las tenías) ---
print("DEBUG: Definiendo funciones de reporte...")
# (Tu función generate_last_detection_csv aquí, sin cambios necesarios por ahora)
def generate_last_detection_csv(results):
    if not results: return None
    output = io.StringIO()
    try:
        # Escribir metadata básica
        output.write(f"Reporte Última Detección\n")
        output.write(f"Timestamp,{results.get('ts', 'N/A')}\n")
        output.write(f"Fuente Datos,{results.get('src', 'N/A')}\n")
        output.write(f"Filas Analizadas,{results.get('rows', 'N/A')}\n")
        output.write(f"Umbral GLM,{results.get('thr', 'N/A')}\n\n")

        # Escribir Métricas
        metrics = results.get('metrics', {})
        if metrics:
            output.write("Metricas Modelo:\nMetrica,Valor\n")
            # Escribir métricas simples
            simple_metrics = {k: v for k, v in metrics.items() if isinstance(v, (int, float, str, bool)) and k not in ['report', 'confusion_matrix', 'classes']}
            for name, value in simple_metrics.items():
                output.write(f"{name.replace('_', ' ').title()},{value}\n")

            # Escribir Reporte de Clasificación si existe y es dict
            report = metrics.get('report', {})
            if report and isinstance(report, dict):
                output.write("\nReporte Clasificacion:\n")
                try:
                    pd.DataFrame(report).transpose().to_csv(output, index=True, header=True, float_format='%.4f')
                except Exception as e_rep_csv:
                     output.write(f"Error_generando_reporte_clasificacion,{e_rep_csv}\n")

            # Escribir Matriz de Confusión si existe
            cm = metrics.get('confusion_matrix')
            if cm is not None:
                output.write("\nMatriz Confusion:\n")
                try:
                    cm_arr = np.array(cm)
                    classes = metrics.get('classes', ['BENIGN', 'ATTACK']) # Obtener o usar default
                    output.write("," + ",".join([f"Prediccion {c}" for c in classes]) + "\n")
                    for i, row_data in enumerate(cm_arr):
                        output.write(f"Real {classes[i]}," + ",".join(map(str, row_data)) + "\n")
                except Exception as e_cm_csv:
                     output.write(f"Error_generando_matriz_confusion,{e_cm_csv}\n")

        # Escribir Resumen de Detecciones
        summary = results.get('summary', {})
        if summary:
            output.write("\nResumen Detecciones:\nEtiqueta,Cantidad\n")
            for label, count in summary.items():
                output.write(f"{label},{count}\n")

        # Escribir Vista Previa de Resultados (Head)
        head = results.get('head', [])
        if head:
            output.write("\nVista Previa Resultados (Primeras Filas):\n")
            try:
                 pd.DataFrame(head).to_csv(output, index=False, header=True)
            except Exception as e_head_csv:
                 output.write(f"Error_generando_vista_previa,{e_head_csv}\n")

        output.seek(0)
        return output.getvalue()
    except Exception as e_csv:
        print(f"Error generando CSV completo: {e_csv}")
        return None # Retorna None si hubo error

print("DEBUG: Funciones reporte OK.")

# --- Helper para Gráficos (MODIFICADO para devolver filename) ---
print("DEBUG: Definiendo funciones gráficos...")
def generate_plot_base64_and_save(plot_func, *args, **kwargs):
    """Genera plot, lo guarda en archivo y devuelve URL base64 y nombre de archivo."""
    img_buffer = io.BytesIO()
    fig = None
    filename = None
    filepath = None
    # Usar config de app o default seguro
    save_dir = kwargs.pop('save_dir', app.config.get('SAVED_PLOTS_FOLDER', os.path.join(BASE_DIR, 'saved_plots')))
    save_plot = kwargs.pop('save_plot', True) # Guardar por defecto

    try:
        fig = plt.figure(figsize=kwargs.pop('figsize', (6, 4))) # Ajustar tamaño si es necesario

        # Llama a la función que realmente dibuja el gráfico (pasándole fig)
        plot_func(fig=fig, *args, **kwargs)

        plt.tight_layout() # Ajustar layout antes de guardar
        plt.savefig(img_buffer, format='png', bbox_inches='tight')
        img_buffer.seek(0)
        base64_url = f"data:image/png;base64,{base64.b64encode(img_buffer.getvalue()).decode('utf8')}"

        # Guardar también en archivo si se requiere
        if save_plot:
            if not save_dir:
                print("WARN plot_save: Directorio para guardar gráficos (save_dir) no configurado.")
            else:
                # Asegurarse que el directorio exista
                os.makedirs(save_dir, exist_ok=True)
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                # Crear nombre base seguro
                base_filename_raw = kwargs.get('title', 'plot').replace(' ', '_')
                base_filename = "".join(c for c in base_filename_raw if c.isalnum() or c in ('_', '-')).rstrip() or "plot"
                filename = f"{base_filename}_{ts}.png"
                filepath = os.path.join(save_dir, filename)
                try:
                    # Guardar la figura desde el buffer para evitar redibujar
                    with open(filepath, 'wb') as f:
                        f.write(img_buffer.getvalue())
                    print(f"INFO: Gráfico guardado en: {filepath}")
                except Exception as e_save:
                    print(f"ERROR al guardar gráfico en archivo {filepath}: {e_save}")
                    filename = None # No se guardó, resetear filename
        # Devolver URL y nombre de archivo (puede ser None si no se guardó)
        return base64_url, filename

    except Exception as e:
        print(f"ERROR generando/guardando plot: {e}\n{traceback.format_exc()}")
        return None, None # Devuelve None para ambos si hay error
    finally:
        if fig:
            plt.close(fig) # ¡Muy importante cerrar la figura para liberar memoria!

# Función específica para graficar CM (sin cambios internos, solo usa el helper)
def plot_confusion_matrix_func(cm, fig, classes=None, title='Matriz Confusión'):
    if classes is None: classes = ['BENIGN', 'ATTACK'] # Default classes
    ax = fig.add_subplot(111)
    cm_arr = np.array(cm)
    # Usar annot_kws para ajustar tamaño de fuente si es necesario
    sns.heatmap(cm_arr, annot=True, fmt='d', cmap='Blues', ax=ax, cbar=False,
                xticklabels=classes, yticklabels=classes, annot_kws={"size": 10})
    ax.set_xlabel('Predicción')
    ax.set_ylabel('Real')
    ax.set_title(title)
    # tight_layout se llama en generate_plot_base64_and_save

print("DEBUG: Funciones gráficos OK.")


# --- RUTAS AUTENTICACIÓN (Sin cambios, asumiendo que funcionan) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        # Verificar usuario y contraseña
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            flash(f'Inicio de sesión exitoso para {user.username}.', 'success')
            next_page = request.args.get('next')
            # Redirección segura
            if next_page and urlparse(next_page).netloc == '':
                print(f"DEBUG: Redirigiendo a 'next' page: {next_page}")
                return redirect(next_page)
            else:
                print("DEBUG: Redirigiendo al dashboard.")
                return redirect(url_for('dashboard'))
        else:
            flash('Login fallido. Verifica usuario y contraseña.', 'error')
            print(f"WARN: Login fallido para usuario: {form.username.data}")
    # Renderizar plantilla de login para GET o si falla la validación POST
    return render_template('login.html', title='Iniciar Sesión', form=form)

@app.route('/logout')
@login_required # Solo usuarios logueados pueden desloguearse
def logout():
    logout_user()
    flash('Has cerrado sesión correctamente.', 'info')
    print("INFO: Usuario cerró sesión.")
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)
            # El primer usuario registrado es admin
            user.is_admin = (User.query.count() == 0)
            db.session.add(user)
            db.session.commit()
            flash(f'¡Cuenta creada para {form.username.data}! Ahora puedes iniciar sesión.', 'success')
            print(f"INFO: Nuevo usuario registrado: {form.username.data}{' (admin)' if user.is_admin else ''}")
            return redirect(url_for('login'))
        except ValidationError as ve:
             # Los errores de validación del formulario ya los maneja WTF al renderizar
             print(f"WARN: Error de validación en registro: {ve}")
             # No es necesario flashear aquí, el campo mostrará el error
        except Exception as e:
            db.session.rollback() # Revertir si falla el commit
            err_msg = str(e)
            # Intentar dar mensajes más específicos
            if 'Duplicate entry' in err_msg:
                if f"'{form.username.data}'" in err_msg and 'for key \'users.username\'' in err_msg:
                     flash('Error: El nombre de usuario ya existe.', 'error')
                elif f"'{form.email.data}'" in err_msg and 'for key \'users.email\'' in err_msg:
                     flash('Error: El email ya está registrado.', 'error')
                else:
                     flash(f'Error de base de datos (duplicado): {err_msg}', 'error')
            else:
                flash(f'Error al crear la cuenta: {err_msg}', 'error')
            print(f"ERROR al registrar usuario {form.username.data}: {e}\n{traceback.format_exc()}")
        # Si hay error de validación o excepción, re-renderizar el formulario
        return render_template('register.html', title='Registro', form=form)

    # Renderizar para la solicitud GET inicial
    return render_template('register.html', title='Registro', form=form)


# --- RUTAS PRINCIPALES ---
# Ruta Dashboard Corregida
@app.route('/')
@login_required # Requiere login para ver el dashboard
def dashboard():
    print("DEBUG: Accediendo a /dashboard")
    active_alerts = []
    last_detection = None
    model_status = "No Disponible"
    recent_alerts = []
    try:
        # Obtener alertas no revisadas (asume que el manager lo maneja)
        active_alerts = alert_manager.get_alerts(show_all=False)

        # Obtener historial y la última detección
        detection_history = alert_manager.get_detection_history()
        last_detection = detection_history[-1] if detection_history else None
        print(f"DEBUG: Contenido de 'last_detection' para dashboard: {last_detection}")

        # --- CORRECCIÓN: Verificar si el modelo está cargado ---
        # Asumiendo que ThreatDetector tiene un atributo 'model' que es None si no está cargado
        model_is_loaded = (detector is not None and hasattr(detector, 'model') and detector.model is not None)
        model_status = "Modelo Cargado ✅" if model_is_loaded else "Modelo No Cargado ❌"
        # --- FIN CORRECCIÓN ---

        # Obtener las alertas más recientes (revisadas o no)
        all_alerts_sorted = alert_manager.get_alerts(show_all=True) # Asume que devuelve todas ordenadas
        recent_alerts = all_alerts_sorted[:5] # Tomar las primeras 5

        print(f"DEBUG: Dashboard - Alertas Activas: {len(active_alerts)}, Última Detección: {'Sí' if last_detection else 'No'}, Estado Modelo: {model_status}")

    except AttributeError as ae:
         # Captura específicamente el error si un método/atributo no existe en un manager
         print(f"ERROR: Atributo/Método faltante en manager para dashboard: {ae}")
         flash(f"Error interno: Falta método/atributo en manager ({ae}). Contacta al administrador.", "danger")
         model_status = "Error Interno" # Estado más informativo
    except Exception as e:
        print(f"ERROR cargando datos del dashboard: {e}\n{traceback.format_exc()}")
        flash("Error al cargar los datos del dashboard.", "error")
        # Reiniciar variables para evitar errores en plantilla
        active_alerts, last_detection, model_status, recent_alerts = [], None, "Error", []

    return render_template('dashboard.html',
                           active_alerts_count=len(active_alerts),
                           last_detection=last_detection, # Pasar el diccionario completo
                           model_status=model_status,
                           recent_alerts=recent_alerts) # Pasar lista de diccionarios


# Ruta Gestión de Datos Corregida
@app.route('/data', methods=['GET', 'POST'])
@login_required
def manage_data():
    if request.method == 'POST':
        action = request.form.get('action')
        url = url_for('manage_data') # URL a la que redirigir
        try:
            if action == 'upload':
                if 'file' not in request.files:
                    flash('No se incluyó el archivo en la solicitud.', 'error')
                    return redirect(url)
                file = request.files['file']
                fname = file.filename
                if fname == '':
                    flash('No se seleccionó ningún archivo.', 'warning')
                    return redirect(url)
                if file and allowed_file(fname):
                    fname = secure_filename(fname)
                    fpath = os.path.join(app.config['UPLOAD_FOLDER'], fname)
                    file.save(fpath)
                    # Asume que load_csv_data devuelve (bool_exito, mensaje_o_dataframe)
                    ok, result = data_manager.load_csv_data(fpath)
                    if ok:
                        flash(f"Archivo '{fname}' cargado.", 'success')
                        session['loaded_filepath'] = fpath # Guardar ruta
                        session.pop('processed_data_info', None) # Limpiar estado procesado anterior
                    else:
                        flash(f"Error al cargar '{fname}': {result}", 'error')
                        session.pop('loaded_filepath', None)
                elif file:
                    flash(f"Tipo de archivo no permitido: '{fname}'. Solo CSV.", 'error')

            elif action == 'preprocess':
                # Obtener los datos que fueron cargados previamente DESDE EL MANAGER
                df_loaded = data_manager.get_loaded_data() # Asume que esta función devuelve el DF o None

                if df_loaded is not None and not df_loaded.empty: # Verificar que hay datos válidos
                    print("INFO: Intentando preprocesar datos cargados...")
                    try:
                        # --- CORRECCIÓN: PASAR el DataFrame cargado a preprocess_data ---
                        # Y recibir la tupla (DataFrame | None, mensaje)
                        processed_df_result, msg = data_manager.preprocess_data(df_loaded)
                        # Nota: preprocess_data ahora también guarda internamente en data_manager.processed_data si tiene éxito

                        if processed_df_result is not None: # Verificar éxito del preprocesamiento
                            flash(msg, 'success')
                            # Guarda/Actualiza info en sesión sobre los datos procesados
                            session['processed_data_info'] = {
                                'rows': len(processed_df_result),
                                'cols': len(processed_df_result.columns),
                                'ts': datetime.datetime.now().isoformat(timespec='seconds'),
                                'source_file': os.path.basename(session.get('loaded_filepath', 'N/A'))
                            }
                            print(f"DEBUG: Datos procesados info actualizada: {session['processed_data_info']}")
                        else: # Si preprocess_data devolvió None (falló)
                            flash(f"Error en preprocesamiento: {msg}", 'error')
                            # Quitar info de procesado anterior si la hubiera
                            session.pop('processed_data_info', None)
                            # Mantener el archivo cargado en sesión para intentar de nuevo si quiere
                    except Exception as e_proc_call:
                         # Capturar errores inesperados al llamar a preprocess_data
                         print(f"ERROR llamando/procesando data_manager.preprocess_data: {e_proc_call}\n{traceback.format_exc()}")
                         flash(f"Error crítico durante el preprocesamiento: {e_proc_call}", "danger")
                         session.pop('processed_data_info', None)
                else:
                    # Si no había datos cargados en el manager para empezar
                    flash('Error: No hay datos cargados válidos para preprocesar. Intenta cargar el archivo de nuevo.', 'warning')
                    session.pop('processed_data_info', None) # Limpiar por si acaso


            else:
                flash('Acción desconocida solicitada.', 'warning')

        except Exception as e:
            flash(f"Error crítico en gestión de datos: {e}", "error")
            print(f"ERROR manage_data POST: {e}\n{traceback.format_exc()}")
            session.pop('loaded_filepath', None)
            session.pop('processed_data_info', None)
        # Redirigir siempre a la misma página después de un POST
        return redirect(url)

    # --- GET Request ---
    # Preparar datos para mostrar en la plantilla
    loaded_preview_headers = None
    loaded_preview_data = None
    processed_preview_headers = None
    processed_preview_data = None
    p_info = session.get('processed_data_info')
    l_path = session.get('loaded_filepath')
    l_fname = os.path.basename(l_path) if l_path and os.path.exists(l_path) else None

    try:
        # Obtener vista previa del archivo cargado si existe
        if l_fname:
            df_loaded = data_manager.get_loaded_data()
            if df_loaded is not None and not df_loaded.empty:
                df_loaded_head = df_loaded.head(10) # Tomar solo las primeras 10 filas
                loaded_preview_headers = df_loaded_head.columns.tolist()
                # Convertir a lista de listas, manejando NaN para display
                loaded_preview_data = [[item if pd.notna(item) else '' for item in row]
                                       for row in df_loaded_head.values.tolist()]

        # Obtener vista previa de datos procesados si existen
        if p_info:
            df_processed = data_manager.get_processed_data()
            if df_processed is not None and not df_processed.empty:
                df_processed_head = df_processed.head(10)
                processed_preview_headers = df_processed_head.columns.tolist()
                # Convertir a lista de listas, manejando NaN para display
                processed_preview_data = [[item if pd.notna(item) else '' for item in row]
                                          for row in df_processed_head.values.tolist()]

    except Exception as e:
        print(f"ERROR manage_data GET (preparando previews): {e}\n{traceback.format_exc()}")
        flash("Error al preparar vistas previas de datos.", "error")
        # Resetear variables en caso de error
        loaded_preview_headers, loaded_preview_data = None, None
        processed_preview_headers, processed_preview_data = None, None

    # Renderizar plantilla pasando los datos, no el HTML pre-renderizado
    return render_template('data_management.html',
                           loaded_filename=l_fname,
                           processed_info=p_info,
                           loaded_preview_headers=loaded_preview_headers,
                           loaded_preview_data=loaded_preview_data,
                           processed_preview_headers=processed_preview_headers,
                           processed_preview_data=processed_preview_data)

# Ruta Simulador (Sin cambios grandes, asumiendo que funciona)
@app.route('/simulate', methods=['GET', 'POST'])
@login_required
def simulate():
    # (Tu código para /simulate como lo tenías)
    # ...
     if request.method == 'POST':
        try:
            dur = int(request.form.get('duration', 60))
            intensity = int(request.form.get('intensity', 5))
            attacks_raw = request.form.getlist('attacks') if 'attacks' in request.form else []
            attacks = [a.strip() for a in attacks_raw if isinstance(a, str) and a.strip()] or ['Generic Attack']

            if dur <= 0: raise ValueError("Duración debe ser > 0.")
            if not (1 <= intensity <= 10): raise ValueError("Intensidad debe estar entre 1-10.")

            cfg = {"duration": dur, "intensity": intensity, "attacks": attacks}
            print(f"INFO: Solicitud simulación: {cfg}")

            df = simulator.run_simulation(cfg)

            if df is not None and not df.empty:
                sim_id = str(uuid.uuid4())
                fname = f"sim_data_{sim_id}.pkl"
                fpath = os.path.join(app.config['TEMP_SIM_FOLDER'], fname)
                try:
                    df.to_pickle(fpath)
                    print(f"INFO: Datos de simulación guardados en: {fpath}")
                    session['simulation_info'] = {
                        'rows_generated': len(df),
                        'config': cfg,
                        'timestamp': datetime.datetime.now().isoformat(timespec='seconds'),
                        'filepath': fpath
                    }
                    simulator.add_to_history(session['simulation_info'])
                    flash(f'Simulación completada. Generados {len(df)} registros.', 'success')
                except Exception as e_save:
                    flash(f"Error al guardar archivo de simulación: {e_save}", "error")
                    print(f"ERROR guardando pickle de simulación: {e_save}\n{traceback.format_exc()}")
                    session.pop('simulation_info', None)
            else:
                flash('La simulación no generó datos válidos.', 'warning')
                session.pop('simulation_info', None)

        except ValueError as ve:
            flash(f'Entrada inválida para la simulación: {ve}', 'error')
        except Exception as e:
            flash(f'Error inesperado durante la simulación: {e}', 'error')
            print(f"ERROR simulate POST: {e}\n{traceback.format_exc()}")
            session.pop('simulation_info', None)

        return redirect(url_for('simulate'))

    # --- GET Request ---
     print("DEBUG: Procesando GET /simulate")
     sim_info = None
     history = []
     preview_headers = None
     preview_data = None
     try:
         sim_info = session.get('simulation_info')
         history = simulator.get_history()
         if sim_info and sim_info.get('filepath') and os.path.exists(sim_info['filepath']):
             try:
                 df_preview = pd.read_pickle(sim_info['filepath']).head(10)
                 if not df_preview.empty:
                     preview_headers = df_preview.columns.tolist()
                     preview_data = [row.tolist() for _, row in df_preview.iterrows()]
             except Exception as e_load:
                 print(f"WARN: No se pudo cargar/procesar el archivo pickle de simulación: {e_load}")
                 flash("No se pudo cargar la vista previa de la última simulación.", "warning")
     except Exception as e_get_prep:
         print(f"ERROR preparando datos para simulate GET: {e_get_prep}\n{traceback.format_exc()}")
         flash("Error al cargar datos del simulador.", "error")
         sim_info, history, preview_data, preview_headers = None, [], None, None
     return render_template('simulator.html',
                            simulation_history=history,
                            last_simulation_info=sim_info,
                            preview_headers=preview_headers,
                            preview_data=preview_data)


# --- RUTA DETECT CORREGIDA (incluye manejo de filename para plot) ---
@app.route('/detect', methods=['GET', 'POST'])
@login_required
def detect():
    print(f"DEBUG: /detect {request.method}")
    history = alert_manager.get_detection_history() # Obtener historial
    session_res = session.get('last_detection_results') # Resultados de la última ejecución POST

    # Variables para pasar a la plantilla en GET
    model_metrics = None
    evaluation_report_html = None # Renombrado para claridad
    evaluation_cm_plot_url = None # Renombrado para claridad
    evaluation_cm_filename = None # <<< NUEVO: Para guardar nombre archivo EVAL CM
    detection_preview_headers = None # Para la tabla de predicciones
    detection_preview_data = None    # Para la tabla de predicciones
    active_alerts = []
    has_proc = False
    has_sim = False

    # --- POST Request ---
    if request.method == 'POST':
        print("DEBUG: POST /detect")
        df = None
        src_info = "N/A"
        rows_count = 0
        try:
            ds = request.form.get('datasource')
            print(f"DEBUG: Fuente seleccionada: {ds}")

            # Cargar datos según la fuente (igual que antes)
            if ds == 'processed':
                df_proc = data_manager.get_processed_data()
                if df_proc is not None and not df_proc.empty:
                    df = df_proc.copy()
                    src_info = "Datos Preprocesados Cargados"
                    rows_count = len(df)
                    print(f"INFO: Usando {src_info} ({rows_count} filas)")
                else:
                    flash("No hay datos preprocesados disponibles.", "warning")
                    return redirect(url_for('detect'))
            elif ds == 'simulation':
                sim = session.get('simulation_info')
                if sim and sim.get('filepath') and os.path.exists(sim['filepath']):
                    try:
                        print(f"INFO: Cargando datos desde simulación: {sim['filepath']}")
                        df_sim = pd.read_pickle(sim['filepath'])
                        if df_sim is not None and not df_sim.empty:
                            print("INFO: Preprocesando datos de simulación...")
                            # --- CORRECCIÓN: Llamar y manejar resultado ---
                            # Ahora preprocess_data devuelve (DataFrame | None, mensaje)
                            # El resultado procesado se guarda en df_processed_sim_result
                            df_processed_sim_result, preproc_msg = data_manager.preprocess_data(df_sim.copy())

                            if df_processed_sim_result is not None: # Verificar que el preproc. tuvo éxito
                                df = df_processed_sim_result # Usar el dataframe devuelto para la detección
                                src_info = f"Última Simulación ({os.path.basename(sim['filepath'])})"
                                rows_count = len(df)
                                print(f"INFO: Usando {src_info} preprocesados ({rows_count} filas)")
                            else: # Si preprocess_data devolvió None
                                # Lanzar error para que el try/except exterior lo maneje
                                raise RuntimeError(f"Falló preprocesamiento de simulación: {preproc_msg}")
                        else:
                            raise FileNotFoundError("Archivo de simulación vacío.")
                    except Exception as e_ld_sim:
                        print(f"ERROR al cargar o preprocesar simulación: {e_ld_sim}\n{traceback.format_exc()}")
                        flash(f"Error al cargar/preprocesar simulación: {e_ld_sim}", "danger")
                        return redirect(url_for('detect'))
                else:
                    flash("No hay datos de simulación disponibles.", "warning")
                    return redirect(url_for('detect'))
            else:
                flash("Fuente de datos inválida.", "danger")
                return redirect(url_for('detect'))

            # Ejecutar Detección si tenemos DataFrame
            if df is not None and not df.empty:
                final_output = None
                try:
                    print("INFO: Llamando detector.run_detection()")
                    final_output = detector.run_detection(df) # Asume que devuelve dict
                    print("INFO: run_detection completado.")
                except Exception as e_det:
                    print(f"ERROR durante detector.run_detection: {e_det}\n{traceback.format_exc()}")
                    flash(f"Error crítico durante la detección: {e_det}", "danger")
                    final_output = None

                # Procesar Resultados si la detección fue exitosa
                if final_output is not None and isinstance(final_output, dict) and 'data' in final_output:
                    df_res = final_output.get('data')
                    if df_res is not None and not df_res.empty:
                        print("DEBUG: Procesando resultados post-detección...")
                        try:
                            current_threshold = detector.prediction_threshold if hasattr(detector, 'prediction_threshold') else system_config.get('glm_threshold')
                            results_for_session = {
                                'ts': datetime.datetime.now().isoformat(timespec='seconds'),
                                'src': src_info, 'rows': rows_count,
                                'thr': current_threshold, # Guardar umbral usado
                                'metrics': final_output.get('metrics', {}),
                                'summary': final_output.get('detection_summary', {})
                            }
                            # Preparar vista previa para sesión (lista de diccionarios)
                            prev_cols = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'label', 'prediction_label', 'prediction_proba']
                            avail = [c for c in prev_cols if c in df_res.columns]
                            # Asegurarse de formatear float para la sesión/historial
                            df_prev = df_res[avail].head(10) if avail else df_res.head(10)
                            if 'prediction_proba' in df_prev.columns:
                                 df_prev['prediction_proba'] = df_prev['prediction_proba'].map('{:.4f}'.format) # Formatear
                            results_for_session['head'] = df_prev.to_dict('records')

                            session['last_detection_results'] = results_for_session
                            print("DEBUG: Resultados guardados en sesión.")

                            hist_entry = results_for_session.copy(); hist_entry.pop('head', None)
                            alert_manager.add_detection_to_history(hist_entry)
                            print("INFO: Resumen añadido al historial persistente.")

                            if 'prediction_label' in df_res.columns:
                                n_alerts, _ = alert_manager.generate_alerts(df_res)
                                print(f"INFO: {n_alerts} nuevas alertas generadas y guardadas en BD.")
                                if n_alerts > 0: flash(f"{n_alerts} nuevas alertas generadas.", "info")
                            else:
                                print("WARN: Falta 'prediction_label' para generar alertas.")
                                flash("Resultados generados, pero no se pudo generar alertas.", "warning")

                            print("SUCCESS: Post-detección OK.")
                            flash("Detección completada con éxito.", "success")

                        except Exception as e_post:
                            print(f"ERROR procesando resultados post-detección: {e_post}\n{traceback.format_exc()}")
                            flash(f"Error al procesar resultados o generar alertas: {e_post}", "danger")
                    else:
                        print("WARN: DataFrame de resultados de detección vacío.")
                        flash("La detección se ejecutó pero no produjo resultados.", "warning")
                else:
                     print("WARN: La función de detección no devolvió resultados válidos.")
                     flash("La detección no produjo resultados válidos o falló internamente.", "warning")
            else:
                 print("ERROR: No había DataFrame válido para iniciar la detección.")
                 flash("Error interno: No se pudieron preparar los datos para la detección.", "danger")

        except Exception as e_gen_post:
            print(f"ERROR general en POST /detect: {e_gen_post}\n{traceback.format_exc()}")
            flash(f"Error interno grave durante la solicitud de detección: {e_gen_post}", "danger")

        return redirect(url_for('detect')) # Siempre redirigir a GET después de POST

    # --- GET Request ---
    model_metrics = None
    # evaluation_report_html = None # <-- Ya no usaremos esta
    evaluation_report_data = None # <<< NUEVO: Para pasar los datos del reporte >>>
    evaluation_cm_plot_url = None
    evaluation_cm_filename = None
    detection_cm_plot_url = None
    detection_cm_filename = None
    detection_preview_headers = None
    detection_preview_data = None
    active_alerts = []
    has_proc = False
    has_sim = False

    try:
        print("DEBUG: Procesando GET /detect")
        eval_metrics = detector.evaluate_on_test_set() if hasattr(detector, 'evaluate_on_test_set') else None

        if eval_metrics and isinstance(eval_metrics, dict) and eval_metrics.get('accuracy') is not None:
            model_metrics = eval_metrics # Guardar métricas generales (incluye 'report' y 'confusion_matrix')
            print(f"DEBUG: Métricas de evaluación general obtenidas (Accuracy: {model_metrics.get('accuracy')}).")

            # 2. Generar Gráfico CM de Evaluación General (como antes)
            if model_metrics.get('confusion_matrix') is not None:
                # ... (Código para generar evaluation_cm_plot_url y evaluation_cm_filename como antes) ...
                print("DEBUG: Generando plot CM de evaluación GENERAL...")
                try:
                    evaluation_cm_plot_url, evaluation_cm_filename = generate_plot_base64_and_save(
                        plot_confusion_matrix_func, model_metrics['confusion_matrix'],
                        classes=model_metrics.get('classes'), title='Matriz Confusion (Evaluacion General Modelo)',
                        save_plot=True, save_dir=app.config['SAVED_PLOTS_FOLDER']
                    )
                    if evaluation_cm_plot_url: print(f"DEBUG: Plot CM eval generado (Archivo: {evaluation_cm_filename}).")
                except Exception as e_cm_gen:
                     print(f"ERROR generando/guardando plot CM eval: {e_cm_gen}")
                     evaluation_cm_plot_url, evaluation_cm_filename = None, None

            # --- CORRECCIÓN: Preparar datos del reporte para Jinja ---
            # 3. Preparar datos del Reporte de Clasificación de Evaluación
            report_dict = model_metrics.get('report')
            if report_dict and isinstance(report_dict, dict):
                # Pasar el diccionario directamente, Jinja puede manejarlo
                evaluation_report_data = report_dict
                print("DEBUG: Datos del reporte de evaluación listos para plantilla.")
            else:
                print("DEBUG: No hay datos de reporte de clasificación en métricas de evaluación general.")
                evaluation_report_data = None # Asegurar que sea None si no hay reporte
            # --- FIN CORRECCIÓN ---

        else:
            print("INFO: No hay métricas de evaluación general del modelo disponibles.")
            evaluation_report_data = None # Asegurar que sea None

        # 4. Preparar Datos y Gráfico CM de la ÚLTIMA DETECCIÓN (como antes)
        session_res = session.get('last_detection_results')
        if session_res:
            # ... (Código para preparar detection_preview_headers/data como antes) ...
             if isinstance(session_res.get('head'), list) and session_res['head']:
                try:
                    head_records = session_res['head']; detection_preview_headers = list(head_records[0].keys())
                    detection_preview_data = [[row.get(header, '') for header in detection_preview_headers] for row in head_records]
                except Exception as e_head_prep: print(f"ERROR al preparar datos de vista previa: {e_head_prep}"); detection_preview_headers, detection_preview_data = None, None
             else: print("DEBUG: No hay datos de vista previa ('head') en última detección.")

            # ... (Código para generar detection_cm_plot_url y detection_cm_filename como antes) ...
             last_metrics = session_res.get('metrics')
             if last_metrics and isinstance(last_metrics, dict) and last_metrics.get('confusion_matrix') is not None:
                 print("DEBUG: Generando plot CM de la ÚLTIMA DETECCIÓN...")
                 try:
                     detection_cm_plot_url, detection_cm_filename = generate_plot_base64_and_save(
                         plot_confusion_matrix_func, last_metrics['confusion_matrix'], classes=last_metrics.get('classes'),
                         title='Matriz Confusion (Ultima Deteccion)', save_plot=True, save_dir=app.config['SAVED_PLOTS_FOLDER']
                     )
                     if detection_cm_plot_url: print(f"DEBUG: Plot CM última detección generado (Archivo: {detection_cm_filename}).")
                 except Exception as e_cm_det: print(f"ERROR generando/guardando plot CM última detección: {e_cm_det}"); detection_cm_plot_url, detection_cm_filename = None, None
             else: print("DEBUG: No hay datos de matriz de confusión en resultados de última detección.")
        else:
            print("DEBUG: No hay resultados de última detección en sesión.")


        # 5. Verificar disponibilidad de datos para el formulario (como antes)
        sim = session.get('simulation_info'); has_sim = sim and sim.get('filepath') and os.path.exists(sim['filepath'])
        df_processed = data_manager.get_processed_data(); has_proc = df_processed is not None and not df_processed.empty
        print(f"DEBUG: Disponibilidad datos para formulario - Sim: {has_sim}, Proc: {has_proc}")

        # 6. Obtener Alertas Activas (como antes)
        print("DEBUG: Obteniendo alertas activas desde BD...")
        try: alerts = alert_manager.get_alerts(show_all=False); print(f"DEBUG: {len(alerts)} alertas activas obtenidas.")
        except Exception as e_al: print(f"ERROR obteniendo alertas activas: {e_al}"); flash("Error al cargar las alertas.", "error"); alerts = []

    except Exception as e_get:
        # ... (Manejo de error general GET como antes) ...
        print(f"ERROR general en GET /detect: {e_get}\n{traceback.format_exc()}")
        flash("Ocurrió un error interno al preparar la página.", "danger")
        model_metrics, evaluation_report_data, evaluation_cm_plot_url, evaluation_cm_filename = None, None, None, None
        detection_cm_plot_url, detection_cm_filename = None, None
        detection_preview_headers, detection_preview_data = None, None
        alerts = []; has_proc, has_sim = False, False

    # 7. Renderizar Plantilla pasando las variables correctas
    print("DEBUG: Renderizando detection.html...")
    return render_template('detection.html',
                           has_processed_data=has_proc,
                           has_simulation_data=has_sim,
                           # Métricas y gráficos de EVALUACIÓN GENERAL
                           current_model_metrics=model_metrics, # Dict completo de métricas (o None)
                           evaluation_report_data=evaluation_report_data, # <<< PASAR DATOS DEL REPORTE >>>
                           evaluation_cm_plot_url=evaluation_cm_plot_url,
                           evaluation_cm_filename=evaluation_cm_filename,
                           # Resultados de la ÚLTIMA DETECCIÓN
                           last_detection_results=session_res,
                           detection_preview_headers=detection_preview_headers,
                           detection_preview_data=detection_preview_data,
                           detection_cm_plot_url=detection_cm_plot_url,
                           detection_cm_filename=detection_cm_filename,
                           # Otros
                           detection_history=history, # Asegúrate que history se obtiene antes del try/except o dentro
                           active_alerts=alerts)

# --- RUTA PARA DESCARGAR GRÁFICOS GUARDADOS ---
@app.route('/download_plot/<path:filename>')
@login_required
def download_plot(filename):
    """ Permite descargar un gráfico previamente guardado en SAVED_PLOTS_FOLDER. """
    print(f"DEBUG: Solicitud descarga gráfico: {filename}")
    # Motivos de seguridad: Validar el nombre del archivo
    safe_filename = secure_filename(filename)
    # Validar que no intente salir del directorio (aunque join lo previene un poco)
    if not safe_filename or '..' in safe_filename or safe_filename.startswith(('/', '\\')):
         print(f"WARN: Intento de descarga de archivo inválido/peligroso: {filename}")
         flash("Nombre de archivo inválido.", "danger")
         # Redirigir a una página segura, como el dashboard
         return redirect(url_for('dashboard'))

    # Usar la configuración de la app para encontrar la carpeta
    plot_dir = app.config.get('SAVED_PLOTS_FOLDER', os.path.join(BASE_DIR, 'saved_plots'))
    # Crear la ruta completa de forma segura
    filepath = os.path.join(plot_dir, safe_filename)
    print(f"DEBUG: Buscando gráfico en ruta absoluta: {filepath}")

    # Verificar que el archivo exista y esté dentro del directorio esperado
    if os.path.exists(filepath) and os.path.commonpath([plot_dir]) == os.path.commonpath([plot_dir, filepath]):
         try:
              # send_file maneja los headers correctos (Content-Type, Content-Disposition)
              # as_attachment=True fuerza la descarga
              print(f"INFO: Enviando archivo de gráfico: {filepath}")
              return send_file(filepath, as_attachment=True)
         except Exception as e:
              print(f"ERROR al enviar archivo de gráfico {filepath}: {e}")
              flash("Error al intentar descargar el gráfico.", "error")
              # Redirigir a detect, donde probablemente estaba el enlace
              return redirect(url_for('detect'))
    else:
         print(f"WARN: Archivo de gráfico no encontrado o fuera del directorio permitido: {filepath}")
         flash("El archivo del gráfico solicitado no se encontró.", "warning")
         return redirect(url_for('detect'))


# --- OTRAS RUTAS (mark_alert_reviewed, download_last_detection_csv, etc.) ---
# (Tu código existente para estas rutas, asegurándote que funcionen)
@app.route('/mark_alert_reviewed/<int:alert_id>', methods=['POST'])
@login_required
def mark_alert_reviewed(alert_id):
    print(f"DEBUG: POST /mark_alert_reviewed/{alert_id}")
    # Determinar a qué página redirigir (intenta obtener de un campo oculto o default a 'detect')
    origin_page = request.form.get('origin', 'detect') # 'detect' como default
    redirect_url = url_for(origin_page) # Generar URL de redirección
    print(f"DEBUG: Origen para redirigir: {origin_page} -> {redirect_url}")

    try:
        # --- CORRECCIÓN AQUÍ ---
        # Llama al método y espera solo UN valor (booleano)
        success = alert_manager.mark_alert_reviewed(alert_id)
        # Genera el mensaje basado en el booleano devuelto
        if success:
            msg = f"Alerta ID {alert_id} marcada como revisada."
            flash(msg, 'success')
            print(f"INFO: Alerta {alert_id} marcada por {current_user.username}.")
        else:
            # El método debería devolver False si no encontró la alerta o falló
            msg = f"No se pudo marcar la alerta {alert_id} como revisada (puede que no exista o hubo un error en BD)."
            flash(msg, 'warning')
            print(f"WARN: No se marcó alerta {alert_id}.")
        # --- FIN CORRECCIÓN ---
    except Exception as e:
        # Captura cualquier otra excepción
        msg = f"Error al intentar marcar alerta {alert_id}: {e}"
        flash(msg, "error")
        print(f"ERROR marcar alerta {alert_id}: {e}\n{traceback.format_exc()}")

    # Redirigir a la página de origen
    return redirect(redirect_url)


@app.route('/report/last_detection_csv')
@login_required
def download_last_detection_csv():
    print("DEBUG: GET /report/last_detection_csv")
    results = session.get('last_detection_results')
    if not results:
        flash("No hay resultados de la última detección disponibles.", "warning")
        return redirect(url_for('detect'))
    try:
        csv_content = generate_last_detection_csv(results) # Usa la función definida antes
        if csv_content is None:
             raise ValueError("La función de generación de CSV devolvió None.")

        response = make_response(csv_content)
        ts_actual = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"reporte_deteccion_{ts_actual}.csv"
        response.headers["Content-Disposition"] = f"attachment; filename=\"{filename}\""
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        print(f"INFO: Reporte CSV generado para descarga: {filename}")
        return response
    except Exception as e:
        print(f"ERROR generando/enviando reporte CSV: {e}\n{traceback.format_exc()}")
        flash(f"Error interno al generar el reporte CSV: {e}", "error")
        return redirect(url_for('detect'))

# --- RUTAS ADMIN ---
@app.route('/admin')
@login_required
@admin_required
def admin_landing():
    print("DEBUG: GET /admin")
    try:
        # Leer config global y de managers
        current_threshold = system_config.get('glm_threshold', 0.7)
        alert_config = alert_manager.config if hasattr(alert_manager, 'config') else {}
        current_severity = alert_config.get('severity_threshold', 'Media')
        current_notify_email = alert_config.get('notify_email', False)
        severity_levels = alert_manager.get_severity_levels() if hasattr(alert_manager, 'get_severity_levels') else ['Baja', 'Media', 'Alta', 'Crítica']
        # Obtener logs
        logs = admin_manager.get_system_logs() if hasattr(admin_manager, 'get_system_logs') else ["Funcionalidad de logs no implementada."]
    except Exception as e:
        print(f"ERROR cargando datos para /admin: {e}")
        flash("Error al cargar la página de administración.", "error")
        current_threshold, current_severity, current_notify_email, severity_levels, logs = 0.7, 'Media', False, ['Baja', 'Media', 'Alta', 'Crítica'], ["Error al cargar logs."]

    # Pasar las configuraciones actuales a la plantilla admin.html
    return render_template('admin.html',
                           glm_threshold=current_threshold,
                           alert_severity_threshold=current_severity,
                           notify_email=current_notify_email,
                           alert_severity_levels=severity_levels,
                           system_logs=logs)


# Ruta para manejar acciones POST desde admin.html
@app.route('/admin/action', methods=['POST'])
@login_required
@admin_required
def admin_actions():
    action = request.form.get('action')
    print(f"INFO: POST /admin/action - Acción recibida: {action}")
    global system_config # Necesario para modificar config global

    try:
        if action == 'update_threshold':
            try:
                thr_str = request.form.get('glm_threshold_admin') # Usar el name del input en admin.html
                if thr_str is None: raise ValueError("Falta umbral GLM en form.")
                thr = float(thr_str)
                if 0.0 <= thr <= 1.0:
                    # Actualizar en el detector y en config global/manager
                    success, msg = admin_manager.update_glm_threshold(thr) # Asume que esta función existe y actualiza donde sea necesario (detector, archivo config)
                    flash(msg, 'success' if success else 'error')
                    if success:
                         system_config['glm_threshold'] = thr # Actualizar también el global en memoria
                         print(f"INFO: Umbral GLM -> {thr} actualizado por admin {current_user.username}.")
                else:
                    flash("Umbral GLM debe estar entre 0.0 y 1.0.", "warning")
            except ValueError:
                flash("Valor de umbral GLM inválido. Debe ser numérico.", 'error')
            except Exception as e_thr:
                flash(f"Error al actualizar umbral GLM: {e_thr}", "danger")
                print(f"ERROR update_threshold action: {e_thr}\n{traceback.format_exc()}")

        elif action == 'update_alert_config':
            sev = request.form.get('alert_severity_threshold_admin') # Usar name del select en admin.html
            notify = request.form.get('notify_email_admin') == 'on' # Usar name del checkbox en admin.html
            if hasattr(alert_manager, 'update_config'):
                 if alert_manager.update_config(severity_threshold=sev, notify_email=notify):
                      flash("Configuración de alertas actualizada.", "success")
                      print(f"INFO: Config alertas (Sev:{sev}, Email:{notify}) actualizada por admin {current_user.username}.")
                 else:
                      flash("Error al actualizar la configuración de alertas.", "warning")
            else:
                 flash("Error interno: Gestor de alertas no actualizable.", "danger")

        elif action == 'retrain':
            print("INFO: Solicitud de reentrenamiento recibida.")
            df_proc = data_manager.get_processed_data() # Obtener datos preprocesados
            if df_proc is not None and not df_proc.empty:
                print(f"INFO: Reentrenando modelo con {len(df_proc)} filas de datos preprocesados.")
                try:
                     # Asume que train_and_save_model existe en detector
                     success, msg = detector.train_and_save_model(df_proc) # Podrías añadir opción de sample_fraction
                     flash(msg, 'success' if success else 'danger')
                     if success: print("INFO: Reentrenamiento y guardado de modelo completado.")
                except Exception as e_tr:
                     flash(f"Error durante el reentrenamiento: {e_tr}", "danger")
                     print(f"ERROR en train_and_save_model: {e_tr}\n{traceback.format_exc()}")
            else:
                flash("No hay datos preprocesados disponibles para el reentrenamiento.", 'warning')
                print("WARN: Solicitud de reentrenamiento sin datos preprocesados.")

        elif action == 'delete_all_alerts':
             print("INFO: Admin solicitó borrar todas las alertas.")
             try:
                 success, msg = alert_manager.delete_all_alerts() # Asume que esta función existe
                 flash(msg, 'success' if success else 'error')
                 if success: print("INFO: Todas las alertas borradas.")
             except Exception as e_del:
                 flash(f"Error al borrar alertas: {e_del}", "danger")
                 print(f"ERROR delete_all_alerts: {e_del}")

        else:
            flash(f"Acción de administrador desconocida: '{action}'.", 'warning')
            print(f"WARN: Acción admin desconocida recibida: {action}")

    except Exception as e:
        # Captura errores generales en el manejo de la acción
        flash(f"Error interno al procesar la acción del administrador: {e}", "error")
        print(f"ERROR procesando admin POST action '{action}': {e}\n{traceback.format_exc()}")

    # Redirigir de vuelta a la página de admin después de la acción
    return redirect(url_for('admin_landing'))


# --- RUTAS GESTIÓN USUARIOS (Admin) ---
# (Tu código para /admin/users, /admin/users/new, /admin/users/<id>/edit, /admin/users/<id>/delete)
# Asegúrate que usen los forms correctos y hagan las validaciones/commits
@app.route('/admin/users')
@login_required
@admin_required
def list_users():
    print("DEBUG: GET /admin/users")
    try:
        users = User.query.order_by(User.username).all()
    except Exception as e:
        print(f"Err obtener users: {e}")
        flash("Error cargar users.", "error")
        users = []
    delete_form = DeleteUserForm() # Para el botón de borrar en cada fila
    return render_template('users_list.html', users=users, delete_form=delete_form)

@app.route('/admin/users/new', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    print(f"DEBUG: /admin/users/new {request.method}")
    form = UserAdminForm() # Usa el form de admin
    if form.validate_on_submit():
        try:
            user = User(username=form.username.data, email=form.email.data, is_admin=form.is_admin.data)
            if form.password.data: # Contraseña es obligatoria al crear
                user.set_password(form.password.data)
                db.session.add(user)
                db.session.commit()
                flash(f'Usuario "{user.username}" creado exitosamente.', 'success')
                print(f"INFO: Admin {current_user.username} creó usuario {user.username}.")
                return redirect(url_for('list_users'))
            else:
                flash("La contraseña es obligatoria al crear un nuevo usuario.", "danger")
                # No redirigir, mostrar el error en el formulario
        except ValidationError as ve:
             flash(f"Error de validación: {ve}", 'danger')
             print(f"WARN: ValidErr create user: {ve}")
        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear usuario: {e}', 'danger')
            print(f"ERR crear usuario: {e}")
        # Re-renderizar el formulario si hay error
        return render_template('user_form.html', title='Crear Nuevo Usuario', form=form, is_new=True)
    # Renderizar para GET
    return render_template('user_form.html', title='Crear Nuevo Usuario', form=form, is_new=True)


@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    print(f"DEBUG: /admin/users/{user_id}/edit {request.method}")
    user = User.query.get_or_404(user_id)
    # Pasar originales al form para validación de unicidad
    form = UserAdminForm(original_username=user.username, original_email=user.email)

    if form.validate_on_submit():
        try:
            # Actualizar campos
            user.username=form.username.data
            user.email=form.email.data
            user.is_admin=form.is_admin.data
            password_changed = False
            # Actualizar contraseña SOLO si se proporcionó una nueva
            if form.password.data:
                print(f"INFO: Actualizando contraseña para user {user.username}")
                user.set_password(form.password.data)
                password_changed = True
            db.session.commit()
            flash(f'Usuario "{user.username}" actualizado correctamente.' + (' (Contraseña cambiada)' if password_changed else ''), 'success')
            print(f"INFO: Admin {current_user.username} editó usuario {user.username}. Contraseña cambiada: {password_changed}.")
            return redirect(url_for('list_users'))
        except ValidationError as ve:
             flash(f"Error de validación: {ve}", 'danger')
             print(f"WARN: ValidErr edit user {user_id}: {ve}")
             # No redirigir, mostrar error en el form
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar usuario: {e}', 'danger')
            print(f"ERR edit user {user_id}: {e}")
        # Re-renderizar el formulario si hay error, poblando con datos actuales del user
        form.username.data = user.username
        form.email.data = user.email
        form.is_admin.data = user.is_admin
        return render_template('user_form.html', title=f'Editar Usuario: {user.username}', form=form, user=user, is_new=False)

    elif request.method == 'GET':
        # Poblar el formulario con los datos existentes del usuario
        form.username.data = user.username
        form.email.data = user.email
        form.is_admin.data = user.is_admin
        # No poblar el campo de contraseña

    return render_template('user_form.html', title=f'Editar Usuario: {user.username}', form=form, user=user, is_new=False)


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    print(f"DEBUG: POST /admin/users/{user_id}/delete")
    user_to_delete = User.query.get_or_404(user_id)
    # Evitar que el admin se borre a sí mismo
    if user_to_delete.id == current_user.id:
        flash("No puedes eliminar tu propia cuenta de administrador.", "danger")
        return redirect(url_for('list_users'))

    form = DeleteUserForm() # Usar para validar CSRF si está habilitado
    # Aunque no hay campos, validate_on_submit() verifica el token CSRF
    if form.validate_on_submit():
        try:
            username_deleted = user_to_delete.username
            db.session.delete(user_to_delete)
            db.session.commit()
            flash(f'Usuario "{username_deleted}" eliminado exitosamente.', 'success')
            print(f"INFO: Admin {current_user.username} eliminó usuario {username_deleted} (ID: {user_id}).")
        except Exception as e:
            db.session.rollback()
            flash(f'Error al eliminar el usuario "{user_to_delete.username}": {e}', 'danger')
            print(f"ERROR al eliminar usuario {user_id}: {e}")
    else:
         # Esto puede ocurrir si CSRF falla
         flash("Error en la solicitud de borrado. Intenta de nuevo.", "danger")
         print(f"WARN: Falló validación de formulario al borrar user {user_id} (posiblemente CSRF).")

    return redirect(url_for('list_users'))


# Ruta Settings (Movida aquí para claridad, como la tenías antes)
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    print(f"DEBUG: Accediendo a /settings con método {request.method}")
    global system_config, detector, alert_manager # Necesario para modificar globals/managers

    if request.method == 'POST':
        print("DEBUG: Procesando POST /settings")
        try:
            # Actualizar Umbral GLM
            thr_str = request.form.get('glm_threshold')
            if thr_str is not None:
                 try:
                     thr = float(thr_str)
                     if 0.0 <= thr <= 1.0:
                         if hasattr(detector, 'prediction_threshold'): detector.prediction_threshold = thr
                         system_config['glm_threshold'] = thr
                         # Guardar config en archivo si AdminManager lo hace
                         if hasattr(admin_manager, 'save_system_config'): admin_manager.save_system_config(system_config)
                         flash(f"Umbral de detección actualizado a {thr:.2f}.", "success")
                         print(f"INFO: Umbral GLM -> {thr} actualizado por {current_user.username}.")
                     else: flash("Valor de umbral GLM fuera del rango (0.0 - 1.0).", "warning")
                 except ValueError: flash("Valor de umbral GLM inválido.", "warning")

            # Actualizar Configuración de Alertas
            sev = request.form.get('severity_threshold')
            email = request.form.get('notify_email') == 'on'
            if hasattr(alert_manager, 'update_config'):
                 current_config = alert_manager.config
                 if current_config.get('severity_threshold') != sev or current_config.get('notify_email') != email:
                      if alert_manager.update_config(severity_threshold=sev, notify_email=email):
                           flash("Configuración de alertas actualizada.", "success")
                           print(f"INFO: Configuración alertas (Sev:{sev}, Email:{email}) por {current_user.username}.")
                      else: flash("Error al actualizar la configuración de alertas.", "warning")
            else: print("WARN: alert_manager no tiene método update_config.")

            return redirect(url_for('settings')) # Redirigir a GET para mostrar valores actualizados

        except Exception as e:
            print(f"ERROR procesando POST /settings: {e}\n{traceback.format_exc()}")
            flash(f"Error interno al guardar la configuración: {e}", "danger")
            # No redirigir, mostrar la página GET con el error (o redirigir si prefieres)

    # --- GET Request ---
    try:
        print("DEBUG: Procesando GET /settings")
        current_threshold = detector.prediction_threshold if hasattr(detector, 'prediction_threshold') else system_config.get('glm_threshold', 0.7)
        current_severity = 'Media'; current_notify_email = False; severity_levels = ['Baja', 'Media', 'Alta', 'Crítica']
        if hasattr(alert_manager, 'config'):
             current_severity = alert_manager.config.get('severity_threshold', 'Media')
             current_notify_email = alert_manager.config.get('notify_email', False)
        if hasattr(alert_manager, 'get_severity_levels'):
             severity_levels = alert_manager.get_severity_levels()

        print(f"DEBUG: GET /settings - Valores actuales: Thr={current_threshold}, Sev={current_severity}, Email={current_notify_email}")

        return render_template('settings.html',
                               title='Configuración',
                               glm_threshold=current_threshold,
                               severity_threshold=current_severity,
                               notify_email=current_notify_email,
                               alert_severity_levels=severity_levels)
    except Exception as e:
        print(f"ERROR preparando GET /settings: {e}\n{traceback.format_exc()}")
        flash("Error al cargar la página de configuración.", "danger")
        return render_template('settings.html', title='Configuración', glm_threshold=0.7, severity_threshold='Media', notify_email=False, alert_severity_levels=['Baja', 'Media', 'Alta', 'Crítica'])


# --- Creación de Tablas y Ejecución ---
if __name__ == '__main__':
    with app.app_context():
        print("INFO: Verificando/Creando tablas de BD si no existen...")
        t_start = datetime.datetime.now()
        try:
            db.create_all() # Crea tablas definidas en modelos (User) si no existen
            t_end = datetime.datetime.now()
            print(f"INFO: db.create_all() completado en {(t_end - t_start).total_seconds():.2f} segundos.")

            # Crear usuario admin inicial si no existe ninguno
            if User.query.count() == 0:
                print("INFO: No existen usuarios. Creando usuario 'admin' inicial...")
                try:
                    admin_user = User(username='admin', email='admin@example.com', is_admin=True)
                    # ¡Usa una contraseña segura por defecto o pídela! Esto es solo un ejemplo.
                    admin_user.set_password('ChangeMe123!')
                    db.session.add(admin_user)
                    db.session.commit()
                    print("INFO: Usuario 'admin' creado con contraseña 'ChangeMe123!'. ¡CAMBIARLA INMEDIATAMENTE!")
                    # No usar flash aquí porque ocurre antes de que el request context exista
                except Exception as e_adm:
                    db.session.rollback()
                    print(f"ERROR crítico al crear usuario admin inicial: {e_adm}")

        except Exception as e_db_init:
            # Errores comunes aquí son credenciales incorrectas, DB no existe, servidor no corriendo
            print(f"FATAL ERROR al inicializar la base de datos con db.create_all(): {e_db_init}")
            print("Verifica la configuración de conexión en DB_CONFIG (usuario, pass, host, dbname) y que el servidor MySQL esté corriendo.")
            exit() # Salir si no se puede conectar a la BD

    print("INFO: Iniciando servidor Flask...")
    # host='0.0.0.0' permite conexiones desde otras máquinas en la red
    # debug=True es útil para desarrollo (auto-recarga, mensajes de error detallados)
    # ¡NUNCA uses debug=True en producción!
    app.run(host='0.0.0.0', port=5000, debug=True)