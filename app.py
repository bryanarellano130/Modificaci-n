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
# Usar bcrypt directamente es más seguro que depender solo de Werkzeug para hash
import bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
# --- FIN IMPORTACIONES LOGIN Y BD ---

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, make_response, send_file
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet


# Importa tus clases manager
try:
    from data_manager import DataManager
    from threat_simulator import ThreatSimulator
    from threat_detector import ThreatDetector
    from alert_manager import AlertManager
    from admin_manager import AdminManager
except ImportError as e:
    print(f"FATAL ERROR: No se pudo importar clase manager: {e}"); exit()

from functools import wraps 

print("DEBUG: Definiendo decorador admin_required...")
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Acceso no autorizado. Solo para administradores.", "error")
            return redirect(url_for('dashboard')) # O url_for('login') si prefieres
        return f(*args, **kwargs)
    return decorated_function

# --- Configuración de la App ---
print("DEBUG: Creando instancia de Flask app...")
app = Flask(__name__)
print("DEBUG: Instancia Flask creada.")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "d3v3l0pm3nt_s3cr3t_k3y_pl34s3_ch4ng3_v4") # Cambié un poco por si acaso

# Carpetas
UPLOAD_FOLDER = 'uploads'
TEMP_SIM_FOLDER = 'temp_sim_data'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TEMP_SIM_FOLDER'] = TEMP_SIM_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'csv'}
print(f"DEBUG: Carpetas configuradas: UPLOAD={app.config['UPLOAD_FOLDER']}, TEMP_SIM={app.config['TEMP_SIM_FOLDER']}")

# --- CONFIGURACIÓN DE BASE DE DATOS (¡¡¡AJUSTAR!!!) ---
DB_USER = "root"
DB_PASS = "" # Contraseña VACÍA por defecto en XAMPP. ¡CAMBIAR si pusiste una!
DB_HOST = "localhost"
DB_NAME = "cyber_db"
db_uri = f'mysql+mysqlconnector://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}'
print(f"DEBUG: Configurando URI de BD: {db_uri[:db_uri.find('@')+1]}********")
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False

# --- INICIALIZACIÓN DE EXTENSIONES ---
print("DEBUG: Inicializando SQLAlchemy...")
try: db = SQLAlchemy(app); print("DEBUG: SQLAlchemy inicializado.")
except Exception as e_sql: print(f"FATAL ERROR: Inicializando SQLAlchemy: {e_sql}"); exit()

print("DEBUG: Inicializando LoginManager...")
try: login_manager = LoginManager(app); print(f"DEBUG: LoginManager instanciado: {login_manager}"); login_manager.login_view = 'login'; login_manager.login_message = "Por favor, inicia sesión."; login_manager.login_message_category = "info"; print("DEBUG: Configuración LoginManager completa.")
except Exception as e_login: print(f"FATAL ERROR: Inicializando LoginManager: {e_login}"); exit()
# --- FIN INICIALIZACIÓN ---

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['TEMP_SIM_FOLDER'], exist_ok=True)

# --- Instancias Globales (Managers) ---
def allowed_file(filename):
    """Verifica si la extensión del archivo está permitida."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
try: print("DEBUG: Inicializando Managers..."); data_manager = DataManager(); simulator = ThreatSimulator(); alert_manager = AlertManager(); model_file_path = None; detector = ThreatDetector(); admin_manager = AdminManager(detector_instance=detector); print("DEBUG: Managers inicializados.")
except Exception as e: print(f"FATAL ERROR inicializando manager: {e}\n{traceback.format_exc()}"); exit()

detection_history = []

# --- MODELO DE BASE DE DATOS (USUARIO) ---
print("DEBUG: Definiendo modelo User...")
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False) # Bcrypt hash tiene 60 chars
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    

    # --- MÉTODO set_password (CORRECTAMENTE FORMATEADO) ---
    def set_password(self, password):
        """Hashea la contraseña y la guarda."""
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
        

    # --- MÉTODO check_password (CORRECTAMENTE FORMATEADO) ---
    def check_password(self, password):
        """Verifica una contraseña contra el hash guardado."""
        # Comprobar primero si hay hash guardado
        if not self.password_hash:
             return False
        try:
            password_bytes = password.encode('utf-8')
            stored_hash_bytes = self.password_hash.encode('utf-8')
            return bcrypt.checkpw(password_bytes, stored_hash_bytes)
        except Exception as e:
             # Loggear el error es importante en producción
             print(f"ERROR verificando password para user {self.id}: {e}")
             return False # Ser cauto y devolver False si hay error

    def __repr__(self):
        return f'<User {self.username}>'
print("DEBUG: Modelo User definido.")

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    try: return User.query.get(int(user_id))
    except Exception as e: print(f"Error cargando user_id {user_id}: {e}"); return None

# --- FORMULARIOS (Flask-WTF) ---
print("DEBUG: Definiendo Formularios...")
class LoginForm(FlaskForm): username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)]); password = PasswordField('Contraseña', validators=[DataRequired()]); remember_me = BooleanField('Recuérdame'); submit = SubmitField('Iniciar Sesión')
class RegistrationForm(FlaskForm): username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)]); email = StringField('Email', validators=[DataRequired(), Email()]); password = PasswordField('Contraseña', validators=[DataRequired(), Length(min=6)]); confirm_password = PasswordField('Confirmar Contraseña', validators=[DataRequired(), EqualTo('password', message='Las contraseñas no coinciden.')]); submit = SubmitField('Registrarse')
def validate_username(self, username):
        if User.query.filter_by(username=username.data).first(): raise ValidationError('Usuario ya existe.')
        def validate_email(self, email):
            if User.query.filter_by(email=email.data).first(): raise ValidationError('Email ya registrado.')
print("DEBUG: Formularios definidos.")

print("DEBUG: Definiendo Formularios Admin User...")

class UserAdminForm(FlaskForm):
    """Formulario base para Crear y Editar usuarios desde el panel Admin."""
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    # La contraseña es opcional al editar, solo necesaria para crear o cambiar
    password = PasswordField('Contraseña (dejar vacío para no cambiar)')
    is_admin = BooleanField('Es Administrador')
    submit = SubmitField('Guardar Usuario')

    # Validadores personalizados para verificar unicidad de username y email
    # Se llamarán automáticamente si el campo tiene un validador con el mismo nombre
    def __init__(self, original_username=None, original_email=None, *args, **kwargs):
        super(UserAdminForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email

    def validate_username(self, username):
        # Solo validar si el username ha cambiado
        if username.data != self.original_username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Este nombre de usuario ya está en uso.')

    def validate_email(self, email):
        # Solo validar si el email ha cambiado
        if email.data != self.original_email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Este email ya está registrado.')

class DeleteUserForm(FlaskForm):
    """Formulario simple para confirmar la eliminación de un usuario."""
    submit = SubmitField('Eliminar Usuario')

print("DEBUG: Formularios Admin User definidos.")

# --- Context Processor ---
@app.context_processor
def inject_current_year(): return {'current_year': datetime.datetime.now().year}

# --- Filtro Jinja2 para Fechas ---
@app.template_filter('format_datetime')
def format_datetime_filter(iso_string, format='%Y-%m-%d %H:%M:%S'):
    if not iso_string: return "N/A";
    try: dt = datetime.datetime.fromisoformat(iso_string); return dt.strftime(format);
    except: return iso_string
    
    print("DEBUG: Definiendo funciones de reporte...")

def generate_last_detection_csv(detection_results):
    """Genera el contenido CSV para los últimos resultados de detección."""
    if not detection_results:
        return None

    output = io.StringIO()

    # Añadir información de resumen
    output.write("Reporte de Última Detección\n")
    output.write(f"Timestamp: {detection_results.get('timestamp', 'N/A')}\n")
    output.write(f"Fuente de Datos: {detection_results.get('source_info', 'N/A')}\n")
    output.write(f"Filas Analizadas: {detection_results.get('rows_analyzed', 'N/A')}\n")
    output.write(f"Umbral del Modelo: {detection_results.get('model_threshold', 'N/A')}\n\n")

    # Añadir métricas
    metrics = detection_results.get('metrics', {})
    if metrics:
        output.write("Métricas del Modelo:\n")
        # Intenta añadir métricas simples como accuracy, precisión, etc.
        simple_metrics = {k: v for k, v in metrics.items() if not isinstance(v, (dict, list))}
        for name, value in simple_metrics.items():
            output.write(f"{name.replace('_', ' ').title()},{value}\n")

        # Manejar reporte de clasificación si está presente
        classification_report = metrics.get('report', {})
        if classification_report and isinstance(classification_report, dict):
             output.write("\nReporte de Clasificación:\n")
             try:
                 # Convertir el diccionario del reporte a DataFrame de pandas
                 # Asumimos que el reporte tiene la estructura { 'clase': { 'metricas' }, ... }
                 report_df = pd.DataFrame(classification_report).transpose()
                 # Escribir el DataFrame a CSV, incluyendo el índice (las clases)
                 report_df.to_csv(output, index=True, header=True)
             except Exception as e:
                 output.write(f"Error al formatear reporte de clasificación en CSV: {e}\n")

    # Añadir resumen de detecciones (conteo por etiqueta)
    summary = detection_results.get('detection_summary', {})
    if summary:
        output.write("\nResumen de Detecciones:\n")
        output.write("Etiqueta,Cantidad\n")
        for label, count in summary.items():
            output.write(f"{label},{count}\n")

    # Añadir vista previa de datos (primeras 100 filas)
    data_head_records = detection_results.get('data_head', [])
    if data_head_records:
        output.write("\nVista Previa de Datos (Primeras 100 filas):\n")
        try:
            # Crear DataFrame desde la lista de diccionarios
            data_head_df = pd.DataFrame(data_head_records)
            # Escribir el DataFrame a CSV, sin el índice numérico de pandas
            data_head_df.to_csv(output, index=False)
        except Exception as e:
            output.write(f"Error al formatear vista previa de datos en CSV: {e}\n")

    output.seek(0) # Volver al inicio del objeto StringIO
    return output.getvalue() # Retornar el contenido como string

print("DEBUG: Funciones de reporte definidas.")

# --- Helper para Gráficos ---
def generate_plot_base64(plot_function, *args, **kwargs):
    """Ejecuta una función de ploteo y devuelve la imagen como base64."""
    # Nivel 1 de indentación (dentro de la función)
    img = io.BytesIO()
    fig = None # Para asegurar que cerramos la figura
    try:
        # Nivel 2 de indentación (dentro de try)
        fig = plt.figure(figsize=kwargs.pop('figsize', (5, 4))) # Permitir pasar figsize
        plot_function(fig=fig, *args, **kwargs) # Pasar figura a la función de ploteo
        plt.savefig(img, format='png', bbox_inches='tight') # Guardar en buffer
        img.seek(0)
        plot_url = base64.b64encode(img.getvalue()).decode('utf8') # Codificar
        return f"data:image/png;base64,{plot_url}"
    except Exception as e:
        # Nivel 2 de indentación (dentro de except)
        print(f"Error generando gráfico: {e}\n{traceback.format_exc()}")
        return None
    finally:
        # Nivel 2 de indentación (dentro de finally)
        # Asegurar que la figura se cierra siempre para liberar memoria
        if fig:
            # Nivel 3 de indentación (dentro de if)
            plt.close(fig)
# --- Fin de la función ---
# --- Rutas de Flask ---
print("DEBUG: Definiendo rutas Flask...")

print("DEBUG: Definiendo funciones de gráficos...")

# Asegúrate de que generate_plot_base64 esté definida antes de esta función si la pones después

def plot_confusion_matrix_func(cm, fig, classes=['BENIGN', 'ATTACK'], title='Matriz de Confusión'):
    """
    Genera un plot de la matriz de confusión en la figura de matplotlib proporcionada.
    Args:
        cm (list or np.array): La matriz de confusión (ej: [[TN, FP], [FN, TP]]).
        fig (matplotlib.figure.Figure): La figura de matplotlib donde dibujar.
        classes (list): Lista de nombres de clases (ej: ['BENIGN', 'ATTACK']).
        title (str): Título del plot.
    """
    try:
        ax = fig.add_subplot(111) # Añadir un subplot a la figura
        # Asegurarse de que cm es un numpy array para seaborn si no lo es ya
        cm_array = np.array(cm)
        sns.heatmap(cm_array, annot=True, fmt='d', cmap='Blues', ax=ax, cbar=False)

        # Etiquetas y título
        ax.set_xlabel('Predicción')
        ax.set_ylabel('Valor Real')
        ax.set_title(title)
        ax.xaxis.set_ticklabels(classes)
        ax.yaxis.set_ticklabels(classes)

        # Asegurar que las etiquetas no se corten
        plt.tight_layout()

    except Exception as e:
        print(f"Error en plot_confusion_matrix_func: {e}\n{traceback.format_exc()}")
        # Puedes añadir un mensaje de error en el plot si quieres, por ejemplo:
        # fig.text(0.5, 0.5, f'Error generando plot:\n{e}', horizontalalignment='center', verticalalignment='center', color='red', fontsize=10)


print("DEBUG: Funciones de gráficos definidas.")

# --- RUTAS DE AUTENTICACIÓN ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Redirigir si ya está autenticado
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm() # Crear instancia del formulario

    # Procesar si el formulario se envió (POST) y es válido
    if form.validate_on_submit():
        # --- CORRECCIÓN: Buscar al usuario ANTES de usar la variable 'user' ---
        user = User.query.filter_by(username=form.username.data).first()

        # --- CORRECCIÓN: Usar if/else multi-línea ---
        # Verificar si se encontró el usuario Y si la contraseña es correcta
        if user and user.check_password(form.password.data):
            # --- Código si el login es exitoso (indentado) ---
            login_user(user, remember=form.remember_me.data)
            flash(f'Inicio de sesión exitoso para {user.username}!', 'success')

            # Redirigir a la página 'next' si existe, o al dashboard
            next_page = request.args.get('next')
            # Comprobación de seguridad para evitar redirecciones abiertas
            if next_page and url_parse(next_page).netloc == '':
                 return redirect(next_page)
            else:
                 return redirect(url_for('dashboard'))
        else:
            # --- Código si el login falla (indentado) ---
            # Si el usuario no existe o la contraseña es incorrecta
            flash('Inicio de sesión fallido. Verifica usuario y contraseña.', 'error')
        # --- Fin del if/else ---

    # Mostrar la plantilla de login para solicitudes GET o si el form no es válido
    return render_template('login.html', title='Iniciar Sesión', form=form)

# app.py

# ... (otras importaciones y código) ...

# Asumiendo que tienes una ruta como esta para descargar resultados
# app.py

# ... (importaciones y otras rutas) ...

# app.py

# ... (importaciones, incluyendo flask_login.logout_user y flask_login.login_required si usas login_required)

# --- Definición de la ruta de Cierre de Sesión ---
@app.route('/logout') # Define la URL de la ruta (ej. /logout)
# @login_required # Opcional: Asegura que solo usuarios autenticados puedan cerrar sesión
def logout():
    """
    Maneja el cierre de sesión del usuario actual.
    """
    logout_user() # Cierra la sesión del usuario actual usando Flask-Login
    flash('Has cerrado tu sesión exitosamente.', 'info') # Muestra un mensaje informativo
    print("INFO: Usuario ha cerrado sesión.")
    return redirect(url_for('login')) # Redirige al usuario a la página de inicio de sesión

# ... (el resto de tus rutas y código en app.py)

@app.route('/download_detection_results', methods=['GET'])
@login_required
def download_detection_results():
    print("DEBUG: Accediendo a ruta /download_detection_results")
    # --- Puedes añadir aquí las líneas TEMPORALES para depurar la sesión ---
    # print(f"DEBUG: Contenido completo de la sesión: {dict(session)}")
    # print(f"DEBUG: session.get('last_detection_results'): {session.get('last_detection_results')}")
    # --- FIN TEMPORAL ---

    # Asegúrate de que los resultados de la última detección estén en la sesión
    last_detection_results = session.get('last_detection_results')

    # Verificar si los resultados existen, tienen la clave 'data', y si el DataFrame no está vacío
    # Es importante que 'data' contenga el DataFrame real, no solo el head
    if last_detection_results and 'data' in last_detection_results and isinstance(last_detection_results['data'], pd.DataFrame) and not last_detection_results['data'].empty:
        try:
            df_results = last_detection_results['data']

            # Preparar el archivo CSV en memoria
            csv_buffer = io.StringIO()
            # Asegurarse de que el DataFrame no tenga índices duplicados si se usó .copy() o alguna manipulación previa
            # También, si hay columnas con caracteres especiales, manejar la codificación si es necesario, pero utf-8 suele ser suficiente.
            df_results.to_csv(csv_buffer, index=False, encoding='utf-8') # Añadir encoding explícito
            csv_buffer.seek(0)

            # Crear una respuesta con el archivo CSV
            response = make_response(csv_buffer.getvalue())
            timestamp_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"detection_results_{timestamp_str}.csv"
            # Configurar headers para la descarga
            response.headers['Content-Disposition'] = f'attachment; filename="{filename}"' # Añadir comillas al nombre del archivo
            response.headers['Content-type'] = 'text/csv; charset=utf-8' # Especificar charset

            print(f"SUCCESS: Archivo CSV '{filename}' generado para descarga.")
            return response

        except Exception as e:
            print(f"ERROR al generar archivo CSV para descarga: {e}\n{traceback.format_exc()}")
            flash(f"Error al generar el archivo CSV para descarga: {e}", "danger")
            return redirect(url_for('detect')) # <<-- CORREGIDO: url_for('detect')

    else:
        print("WARNING: No hay resultados de detección disponibles en la sesión para descargar.")
        flash("No hay resultados de detección disponibles para descargar.", "warning")
        return redirect(url_for('detect')) # <<-- CORREGIDO: url_for('detect')

# ... (el resto de tus rutas y código) ...
# Asegúrate de que tus rutas /logout, /register, etc. estén definidas en app.py

# --- RUTAS PRINCIPALES (Protegidas) ---
@app.route('/')
@login_required
def dashboard():
    try: active_alerts = [a for a in alert_manager.alerts if not a.get('reviewed')]; last_detection_entry = detection_history[-1] if detection_history else None; model_status = "Real" if detector.model else "Simulado"; all_alerts_sorted = alert_manager.get_alerts(show_all=True); recent_alerts = all_alerts_sorted[:5]
    except Exception as e: print(f"ERROR dashboard: {e}\n{traceback.format_exc()}"); flash("Error dashboard.", "error"); active_alerts, last_detection_entry, model_status, recent_alerts = [], None, "Error", []
    return render_template('dashboard.html', active_alerts_count=len(active_alerts), last_detection=last_detection_entry, model_status=model_status, recent_alerts=recent_alerts)

@app.route('/data', methods=['GET', 'POST'])
@login_required
def manage_data():
    if request.method == 'POST':
        action = request.form.get('action'); redirect_url = url_for('manage_data')
        try:
            if action == 'upload':
                if 'file' not in request.files: flash('No se encontró archivo.', 'error'); return redirect(redirect_url)
                file = request.files['file']; filename = file.filename
                if filename == '': flash('No se seleccionó archivo.', 'warning'); return redirect(redirect_url)
                if file and allowed_file(filename):
                    filename = secure_filename(filename); filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename); file.save(filepath)
                    success, message = data_manager.load_csv_data(filepath)
                    # --- Bloque if/else corregido (multi-línea) ---
                    if success:
                        flash(message, 'success')
                        session['loaded_filepath'] = filepath
                        session.pop('processed_data_info', None)
                    else:
                        flash(message, 'error')
                        session.pop('loaded_filepath', None)
                elif file:
                    flash(f"Tipo archivo no permitido.", 'error')
            elif action == 'preprocess':
                if data_manager.loaded_data is not None:
                    success, message = data_manager.preprocess_data()
                    if success:
                        flash(message, 'success')
                        session['processed_data_info'] = {'rows': len(data_manager.processed_data), 'cols': len(data_manager.processed_data.columns), 'timestamp': datetime.datetime.now().isoformat(timespec='seconds')}
                    else:
                        flash(message, 'error')
                        session.pop('processed_data_info', None)
                else:
                    flash('Primero carga archivo CSV.', 'warning')
            else:
                flash('Acción desconocida.', 'warning')
        except Exception as e:
            flash(f"Error inesperado: {e}", "error")
            print(f"ERROR manage_data POST: {e}\n{traceback.format_exc()}")
        return redirect(redirect_url)
    # GET Request
    try: loaded_head_html = data_manager.get_loaded_data_head_html(); processed_head_html = data_manager.get_processed_data_head_html(); processed_info = session.get('processed_data_info'); loaded_filepath = session.get('loaded_filepath'); loaded_filename = os.path.basename(loaded_filepath) if loaded_filepath and os.path.exists(loaded_filepath) else None
    except Exception as e: print(f"ERROR manage_data GET: {e}\n{traceback.format_exc()}"); flash("Error vistas previas.", "error"); loaded_head_html, processed_head_html, processed_info, loaded_filename = "<p>Err</p>", "<p>Err</p>", None, None
    return render_template('data_management.html', loaded_head_html=loaded_head_html, processed_head_html=processed_head_html, loaded_filename=loaded_filename, processed_info=processed_info)

# app.py

# ... (importaciones)
# Asegúrate de que estas importaciones estén presentes si no lo están ya
# from flask_wtf import FlaskForm
# from wtforms import StringField, PasswordField, SubmitField
# from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError # Para la validación del formulario
# import bcrypt # Para el hash de contraseñas
# from .models import User # O donde hayas definido tu modelo User
# from .forms import RegistrationForm # O donde hayas definido tu formulario RegistrationForm
# from your_app import db # Asegúrate de que db esté inicializada globalmente

# Asumo que tu modelo User tiene un método set_password que usa bcrypt

# --- Definición de la ruta de Registro ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Maneja la creación de nuevos usuarios.
    GET muestra el formulario de registro.
    POST procesa los datos del formulario y crea el usuario.
    """
    # Redirigir al dashboard si el usuario ya está autenticado
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    # Instanciar el formulario de registro
    # Asumo que la clase RegistrationForm ya está definida en alguna parte
    form = RegistrationForm()

    # Procesar el formulario si se envió una solicitud POST y es válido
    if form.validate_on_submit():
        try:
            # Crear una nueva instancia de usuario con los datos del formulario
            new_user = User(username=form.username.data, email=form.email.data)

            # Hashear la contraseña antes de guardarla
            # Asumo que tu modelo User tiene un método llamado set_password()
            new_user.set_password(form.password.data) # Esto debería usar bcrypt internamente

            # Opcional: Asignar rol de administrador al primer usuario
            # Si quieres que el primer usuario registrado sea admin
            if User.query.count() == 0:
                new_user.is_admin = True
                print(f"INFO: Primer usuario '{new_user.username}' registrado como administrador inicial.")
            else:
                # Por defecto, los nuevos usuarios no son administradores
                new_user.is_admin = False


            # Añadir el nuevo usuario a la sesión de la base de datos
            db.session.add(new_user)
            # Confirmar los cambios en la base de datos
            db.session.commit()

            # Mostrar un mensaje de éxito
            flash(f'Cuenta creada exitosamente para {form.username.data}! Por favor, inicia sesión.', 'success')
            print(f"INFO: Nuevo usuario registrado: {form.username.data}")

            # Redirigir al usuario a la página de inicio de sesión
            return redirect(url_for('login'))

        except Exception as e:
            # Si ocurre algún error (ej. nombre de usuario o email duplicado si has añadido esas validaciones a nivel de modelo/BD)
            # Revertir la sesión de la base de datos para deshacer los cambios incompletos
            db.session.rollback()
            # Mostrar un mensaje de error al usuario
            flash(f'Error al crear la cuenta: {e}', 'error')
            print(f"ERROR en la ruta /register (POST): {e}\n{traceback.format_exc()}")

    # Renderizar el template de registro (para solicitudes GET o si el POST falla la validación)
    # Se pasa el objeto form al template para mostrar los campos y errores
    return render_template('register.html', title='Registro de Usuario', form=form)

# ... (el resto de tus rutas y código en app.py)

@app.route('/simulate', methods=['GET', 'POST'])
@login_required
def simulate():
    if request.method == 'POST':
        try:
            duration = int(request.form.get('duration', '60')); intensity = int(request.form.get('intensity', '5'))
            attacks_list = request.form.getlist('attacks'); attacks = [a.strip() for a in attacks_list if a.strip()] or ['Attack']
            if duration <= 0: raise ValueError("Duración > 0");
            if not (1 <= intensity <= 10): raise ValueError("Intensidad 1-10")
            config = {"duration": duration, "intensity": intensity, "attacks": attacks}
            print(f"INFO: Solicitud simulación: {config}"); sim_result_df = simulator.run_simulation(config)
            if sim_result_df is not None and not sim_result_df.empty:
                sim_id = str(uuid.uuid4()); temp_filename = f"sim_data_{sim_id}.pkl"; temp_filepath = os.path.join(app.config['TEMP_SIM_FOLDER'], temp_filename)
                try: sim_result_df.to_pickle(temp_filepath); print(f"INFO: Simulación guardada: {temp_filepath}"); session.pop('last_simulation_data', None); session['simulation_ran'] = True; session['last_simulation_filepath'] = temp_filepath; session['simulation_info'] = {'rows_generated': len(sim_result_df), 'config': config, 'timestamp': datetime.datetime.now().isoformat(timespec='seconds'), 'filepath': temp_filepath}; flash(f'Simulación completada ({len(sim_result_df)} registros).', 'success')
                except Exception as e_save: flash(f"Error guardando simulación: {e_save}", "error"); print(f"ERROR guardando pickle: {e_save}\n{traceback.format_exc()}"); session.clear()
            else: flash('Simulación no generó datos.', 'warning'); session.pop('simulation_ran', None); session.pop('last_simulation_filepath', None); session.pop('simulation_info', None)
        except ValueError as ve: flash(f'Entrada inválida: {ve}', 'error')
        except Exception as e: flash(f'Error inesperado simulación: {e}', 'error'); print(f"ERROR simulate POST: {e}\n{traceback.format_exc()}"); session.pop('simulation_ran', None); session.pop('last_simulation_filepath', None); session.pop('simulation_info', None)
        return redirect(url_for('simulate'))
    # GET Request
    try: last_sim_info = session.get('simulation_info'); last_sim_preview_df = None; sim_history = simulator.get_history()
    except Exception as e: print(f"ERROR simulate GET: {e}\n{traceback.format_exc()}"); flash("Error cargando datos simulación.", "error"); last_sim_info, last_sim_preview_df, sim_history = None, None, []
    return render_template('simulator.html', simulation_history=sim_history, last_simulation_info=last_sim_info, last_simulation_preview_df=last_sim_preview_df)

@app.route('/report/last_detection_csv')
@login_required # Protege esta ruta
# @admin_required # Opcional: si solo los admins pueden descargar reportes
def download_last_detection_csv():
    """Ruta para descargar el reporte CSV de la última detección."""
    # Obtener los últimos resultados de detección de la sesión
    last_results = session.get('last_detection_results')

    if not last_results:
        flash("No hay resultados de detección recientes para generar reporte.", "warning")
        return redirect(url_for('detect')) # Redirige de vuelta a la página de detección

    try:
        # Generar el contenido CSV
        csv_content = generate_last_detection_csv(last_results)

        if csv_content is None:
             flash("Error al generar el contenido del reporte CSV.", "error")
             return redirect(url_for('detect'))

        # Crear una respuesta Flask para servir el archivo
        response = make_response(csv_content)

        # Establecer las cabeceras para forzar la descarga y nombrar el archivo
        timestamp_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"reporte_deteccion_{timestamp_str}.csv"
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        response.headers["Content-type"] = "text/csv" # Tipo MIME para CSV

        print(f"INFO: Reporte CSV generado y enviado: {filename}")
        return response # Retorna la respuesta con el archivo

    except Exception as e:
        print(f"ERROR generando reporte CSV: {e}\n{traceback.format_exc()}")
        flash("Error interno al generar el reporte CSV.", "error")
        return redirect(url_for('detect')) # Redirige en caso de error interno

# app.py

# ... (otras importaciones y código) ...

# app.py

# ... (otras importaciones como os, io, base64, pandas, numpy, matplotlib, datetime, traceback, uuid, SQLAlchemy, FlaskForm, wtforms, bcrypt, flask_login, Flask, render_template, request, redirect, url_for, flash, jsonify, session, make_response, send_file, secure_filename, reportlab, etc.) ...
# Importa tus clases manager
# try:
#     from data_manager import DataManager
#     from threat_simulator import ThreatSimulator # Asumimos que tienes la clase ThreatSimulator
#     from threat_detector import ThreatDetector
#     from alert_manager import AlertManager
#     from admin_manager import AdminManager
# except ImportError as e:
#     print(f"FATAL ERROR: No se pudieron importar clases manager: {e}")
#     # Considerar salir o manejar este error de forma adecuada si la app no puede iniciar sin managers
#     exit() # O una forma más robusta de manejar el error

# Asumiendo que las instancias de los managers ya están inicializadas globalmente:
# data_manager = DataManager(...)
# simulator = ThreatSimulator(...) # Asumimos que tienes una instancia global de simulator
# detector = ThreatDetector(...)
# alert_manager = AlertManager(...)
# admin_manager = AdminManager(...)

# Asumiendo que las funciones de gráficos están definidas globalmente:
# def generate_plot_base64(plot_func, data): ...
# def plot_confusion_matrix_func(conf_matrix_data): ...

@app.route('/detect', methods=['GET', 'POST'])
@login_required
def detect():
    """
    Ruta para la página de Detección y Análisis.
    Maneja la visualización de métricas (GET) y la ejecución de detección (POST).
    """
    print(f"DEBUG: Accediendo a ruta /detect con método {request.method}")

    # Obtener historial al inicio para que esté disponible tanto en POST como en GET
    detection_history = alert_manager.get_detection_history() # <-- Esto obtiene el historial guardado

    # Variables para los resultados de la detección *actual* o última de la sesión POST
    last_detection_results_from_session = session.get('last_detection_results')
    data_head_html = None # Vista previa de datos de la última detección

    # Variables para la EVALUACIÓN del modelo CARGADO (lo que queremos mostrar ahora)
    current_model_metrics = None # Métricas obtenidas de evaluate_on_test_set
    cm_plot_url = None # Plot de la matriz de confusión de la evaluación
    report_df_html = None # HTML del Reporte de clasificación de la evaluación (vamos a generar HTML directamente)

    # --- Procesar Solicitud POST (La lógica de detección que ya tenías, ahora corregida) ---
    if request.method == 'POST':
        print("DEBUG: Procesando solicitud POST para /detect")
        try:
            datasource = request.form.get('datasource')
            print(f"DEBUG: Fuente de datos seleccionada: {datasource}")
            df_to_detect = None
            source_info = "Fuente Desconocida"
            rows_analyzed_count = 0 # Inicializar contador

            if datasource == 'processed':
                processed_data_obj = data_manager.get_processed_data()
                if processed_data_obj is not None and not processed_data_obj.empty:
                    df_to_detect = processed_data_obj.copy() # Trabajar en una copia por seguridad
                    source_info = "Datos Cargados y Preprocesados"
                    rows_analyzed_count = len(df_to_detect)
                    print(f"INFO: Iniciando detección: {source_info} ({rows_analyzed_count} filas)...")
                    # Nota: Los datos preprocesados ya deberían tener nombres de columnas limpios

                else:
                    flash("No hay datos cargados y preprocesados disponibles.", "warning")
                    print("WARN: Intento de detección con datos preprocesados pero no disponibles.")
                    return redirect(url_for('detection')) # Redirigir inmediatamente si no hay datos

            elif datasource == 'simulation':
                # --- USAR INFO DE LA SESIÓN PARA CARGAR DATOS DE SIMULACIÓN ---
                # Usamos la clave 'simulation_info' que es la que usa la ruta /simulate POST
                sim_info_from_session = session.get('simulation_info') # <<-- USAR 'simulation_info'
                if sim_info_from_session and sim_info_from_session.get('filepath') and os.path.exists(sim_info_from_session['filepath']):
                    sim_filepath = sim_info_from_session['filepath']
                    try:
                        print(f"INFO: Cargando datos de simulación desde {sim_filepath}")
                        df_sim_loaded = pd.read_pickle(sim_filepath)
                        if df_sim_loaded is not None and not df_sim_loaded.empty:
                             df_to_detect = df_sim_loaded.copy() # Trabajar en una copia
                             source_info = f"Datos de Simulación ({os.path.basename(sim_filepath)})"
                             rows_analyzed_count = len(df_to_detect)
                             print(f"INFO: Iniciando detección: {source_info} ({rows_analyzed_count} filas)...")

                             # --- Limpiar nombres de columnas de los datos de simulación para alineación ---
                             print("INFO: Limpiando nombres de columnas de los datos de simulación para alineación...")
                             try:
                                 if df_to_detect is not None and not df_to_detect.empty:
                                     original_sim_cols = df_to_detect.columns.tolist()
                                     # Usar regex=True explícitamente para replace
                                     df_to_detect.columns = df_to_detect.columns.str.strip().str.replace(r'[^\w]+', '_', regex=True).str.lower().str.strip('_')
                                     renamed_sim_cols_dict = {orig: new for orig, new in zip(original_sim_cols, df_to_detect.columns.tolist()) if orig != new}
                                     if renamed_sim_cols_dict:
                                          print(f"INFO: Columnas de simulación renombradas. Ej: {list(renamed_sim_cols_dict.items())[:5]}...")
                                     #else:
                                     #     print("INFO: Nombres de columnas de simulación ya estaban limpios o no cambiaron.")

                             except Exception as e:
                                 print(f"ERROR limpiando nombres de columnas de simulación: {e}")
                                 pass # Continúa ejecución

                        else:
                            flash("El archivo de simulación cargado está vacío.", "warning")
                            print("WARN: Archivo de simulación cargado pero vacío.")
                            return redirect(url_for('detection')) # Redirigir si el archivo está vacío

                    except Exception as e:
                        print(f"ERROR cargando datos de simulación para detección: {e}\n{traceback.format_exc()}")
                        flash(f"Error al cargar datos de simulación para detección: {e}", "danger")
                        return redirect(url_for('detection')) # Redirigir en caso de error de carga

                else:
                    flash("No hay datos de simulación disponibles.", "warning")
                    print("WARN: Intento de detección con datos de simulación pero no disponibles.")
                    return redirect(url_for('detection')) # Redirigir si no hay simulación info/archivo

            else:
                flash("Fuente de datos no válida seleccionada.", "danger")
                print(f"WARN: Fuente de datos no válida seleccionada: {datasource}")
                return redirect(url_for('detection')) # Redirigir si la fuente no es válida


            # --- Ejecutar Detección ---
            # Solo ejecutamos si logramos obtener datos válidos
            detection_output = None
            if df_to_detect is not None and not df_to_detect.empty:
                 try:
                      # Esta es la llamada principal al detector para DETECTAR en datos NUEVOS
                      # run_detection retorna {'data': DataFrameConPredicciones, 'metrics': {}, 'detection_summary': {}}
                      detection_output = detector.run_detection(df_to_detect)
                      print("INFO: Ejecución de detección completada.")
                 except Exception as e:
                      print(f"ERROR durante la ejecución del detector: {e}\n{traceback.format_exc()}")
                      flash(f"Error durante la detección: {e}", "danger")
                      detection_output = None # Asegurar que sea None si falla

            else:
                 # Esto ya se manejó en los bloques de fuente de datos, pero por si acaso
                 print("WARN: No hay datos para pasar al detector. df_to_detect está vacío o None.")
                 flash("No se pudieron obtener datos válidos para la detección.", "warning")


            # --- Guardar Resultados de esta Detección en Sesión e Historial y Generar Alertas ---
            # Solo si la ejecución del detector produjo un output válido (el dict con 'data', 'metrics', 'summary')
            if detection_output is not None and isinstance(detection_output, dict): # Verificar que es un diccionario
                 detection_data_df = detection_output.get('data')

                 # Asegurarnos de que el DataFrame de resultados no está vacío para guardar/alertar
                 if detection_data_df is not None and not detection_data_df.empty:
                      print("DEBUG: Procesando resultados de detección para guardar y alertar...")
                      try:
                          # Información para guardar en sesión e historial
                          results_to_save = {
                              'timestamp': datetime.datetime.now().isoformat(),
                              'source_info': source_info,
                              'rows_analyzed': rows_analyzed_count, # Filas que entraron al proceso (antes de dropna en detector)
                              # Guardar el umbral del modelo *actual* en el historial para referencia
                              'model_threshold': detector.prediction_threshold if detector else None,
                              # Guardar las métricas de esta *detección específica*
                              'metrics': detection_output.get('metrics', {}),
                              'detection_summary': detection_output.get('detection_summary', {}),
                          }
                          # Limitar las filas para la vista previa en sesión
                          max_rows_head = 10
                          # Crear el data_head a partir del DataFrame de resultados
                          # Seleccionar columnas específicas para la vista previa si existen
                          preview_cols = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'label', 'prediction_label', 'prediction_proba']
                          # Asegurarse de que las columnas existen antes de intentar seleccionarlas
                          available_preview_cols = [col for col in preview_cols if col in detection_data_df.columns]

                          # Usar las columnas disponibles para la vista previa
                          preview_df_for_session = detection_data_df[available_preview_cols].head(max_rows_head) if available_preview_cols else detection_data_df.head(max_rows_head)

                          # Convertir a lista de diccionarios para almacenar en la sesión
                          results_to_save['data_head'] = preview_df_for_session.to_dict('records')
                          if available_preview_cols:
                               print("DEBUG: Data head para sesión generado con columnas requeridas.")
                          else:
                               print("WARN: Columnas requeridas para vista previa no encontradas en el DataFrame de resultados. Guardando todas las columnas del head.")


                          # Guardar resultados de la detección en la sesión para mostrar en la próxima carga GET
                          session['last_detection_results'] = results_to_save
                          print("DEBUG: Resultados de la última detección guardados en sesión.")

                          # Añadir resumen al historial (sin data_head para que sea ligero)
                          history_summary = results_to_save.copy()
                          history_summary.pop('data_head', None) # Eliminar data_head antes de añadir al historial
                          alert_manager.add_detection_to_history(history_summary)
                          print("INFO: Resumen de detección añadido al historial.")


                          # --- PASAR EL DATAFRAME COMPLETO CON PREDICCIONES AL ALERTMANAGER ---
                          # El método en AlertManager se llama probablemente 'generate_alerts' (basado en código previo)
                          # Este método en AlertManager debe filtrar DENTRO de sí mismo por 'prediction_label' == 'Attack'
                          if 'prediction_label' in detection_data_df.columns:
                               print(f"INFO: Pasando {len(detection_data_df)} filas de resultados al AlertManager para análisis de alertas...")
                               # USAR EL MÉTODO generate_alerts (el que probablemente existe en tu clase)
                               # Pasa el DataFrame completo a este método.
                               new_alerts_count, created_alerts = alert_manager.generate_alerts(detection_data_df) # <<-- USAR 'generate_alerts'

                               print(f"INFO: ({new_alerts_count}, {len(created_alerts)}) nuevas alertas generadas (cumpliendo umbral '{alert_manager.config.get('severity_threshold', 'Desconocido')}').")
                               if new_alerts_count > 0:
                                    flash(f"{new_alerts_count} nuevas alertas generadas. Revisa la sección de Alertas.", "info")
                          else:
                               # Si por alguna razón prediction_label no está en los resultados (error grave en run_detection)
                               print("WARN: Columna 'prediction_label' no encontrada en los resultados para generar alertas.")
                               flash("No se pudo generar alertas: columna de predicción no disponible.", "warning")
                               new_alerts_count, created_alerts = 0, []
                               print(f"INFO: (0, []) nuevas alertas generadas.")


                          print("SUCCESS: Proceso post-detección (guardar y alertar) completado.")


                      except Exception as e:
                           print(f"ERROR procesando resultados post-detección, historial o alertas: {e}\n{traceback.format_exc()}")
                           flash(f"Error al procesar resultados de detección, historial o alertas: {e}", "danger")

                 else:
                      # Si detection_data_df era None o empty
                      print("WARN: El DataFrame de resultados de detección retornado por run_detection estaba vacío o None.")
                      flash("La detección se ejecutó pero no produjo resultados de datos válidos.", "warning")


            else:
                 # Si detection_output era None o no era un diccionario válido
                 print("WARN: detection_output retornado por run_detection no es válido.")
                 # El mensaje de error de run_detection ya se flasheó antes si falló

        except Exception as e:
            # Capturar cualquier otro error inesperado durante el POST
            print(f"ERROR general en POST /detect: {e}\n{traceback.format_exc()}")
            flash(f"Error interno al iniciar la detección: {e}", "danger")

        # Después de procesar POST, redirigir a la misma ruta GET
        return redirect(url_for('detect'))

    # --- Solicitud GET (Muestra la página de detección) ---
    # Bloque try principal para todo el procesamiento de la solicitud GET
    # Las variables last_detection_results_from_session y detection_history ya se obtuvieron al inicio
    try:
        print("DEBUG: Procesando solicitud GET para /detect")

        # --- Obtener métricas de EVALUACIÓN del modelo CARGADO ---
        print("DEBUG: Evaluando el modelo cargado en el conjunto de prueba para mostrar métricas.")
        # evaluate_on_test_set retorna {'accuracy': ..., 'report': ..., 'confusion_matrix': ...} o estructura de error si no se puede
        evaluation_metrics = detector.evaluate_on_test_set()

        if evaluation_metrics and evaluation_metrics.get('accuracy') is not None:
            current_model_metrics = evaluation_metrics
            print("DEBUG: Métricas de evaluación del modelo cargado obtenidas.")

            # Procesar Plot de Matriz de Confusión de la evaluación
            if current_model_metrics.get('confusion_matrix') is not None:
                try:
                    # Asegurarse de que plot_confusion_matrix_func y generate_plot_base64 están definidas
                    # Asumiendo que generate_plot_base64 está definida en app.py
                    cm_plot_url = generate_plot_base64(plot_confusion_matrix_func, current_model_metrics['confusion_matrix'])
                    print("DEBUG: Plot CM de evaluación generado.")
                except Exception as e:
                    print(f"ERROR generando plot CM de evaluación: {e}\n{traceback.format_exc()}")
                    cm_plot_url = None
                    flash("Error al generar la gráfica de Matriz de Confusión.", "warning")

            # Procesar Reporte de Clasificación de la evaluación
            if current_model_metrics.get('report') is not None and isinstance(current_model_metrics['report'], dict):
                 try:
                      # Convertir el diccionario del reporte a DataFrame y luego a HTML
                      report_df = pd.DataFrame(current_model_metrics['report']).transpose()
                      # Formatear a 4 decimales para la vista previa
                      report_df_html = report_df.to_html(classes=['data-table', 'table-sm'], border=0, float_format='%.4f')
                      print("DEBUG: Reporte de evaluación convertido a DataFrame y HTML.")
                 except Exception as e:
                      print(f"WARN: Falló la conversión del reporte de evaluación (dict a DF/HTML): {e}\n{traceback.format_exc()}")
                      report_df_html = "<p>Error al generar el reporte de clasificación.</p>"
                      flash("Error al procesar el reporte de clasificación.", "warning")
            elif current_model_metrics.get('report') is not None:
                 # Si el reporte no es un diccionario (ej. es un string de error)
                 report_df_html = f"<p>Reporte de evaluación: {current_model_metrics['report']}</p>"


        else:
            print("INFO: No se pudieron obtener métricas de evaluación del modelo cargado o la evaluación falló.")
            # evaluation_metrics puede contener un reporte de error aunque accuracy sea None
            if evaluation_metrics and evaluation_metrics.get('report'):
                 print(f"INFO: Mensaje del reporte de evaluación: {evaluation_metrics['report']}")
                 report_df_html = f"<p>Métricas no disponibles. {evaluation_metrics['report']}</p>" # Mostrar mensaje de error de evaluación
            else:
                 report_df_html = "<p>Métricas de evaluación del modelo no disponibles.</p>" # Mensaje genérico si no hay info de evaluación


        # --- Preparar Vista Previa de Datos de la última Detección (desde la sesión) ---
        # last_detection_results_from_session ya se obtuvo al inicio del request
        # Acceder a los datos de la vista previa guardados en la sesión
        data_head_records = last_detection_results_from_session.get('data_head') if last_detection_results_from_session else None

        if data_head_records: # Verificar si hay registros en data_head
            print("DEBUG: Generando HTML para vista previa de datos de la última detección (desde sesión).")
            try:
                preview_df = pd.DataFrame(data_head_records)
                # Columnas que queremos mostrar en la tabla de vista previa
                # Asegurarse de que 'label' está presente si es posible (si la detección fue en datos con etiquetas)
                preview_cols_order = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'label', 'prediction_label', 'prediction_proba']
                # Seleccionar solo las columnas que existen en el DataFrame de la sesión y en el orden deseado
                available_and_ordered_preview_cols = [col for col in preview_cols_order if col in preview_df.columns]

                if available_and_ordered_preview_cols:
                     # Usar el gestor de datos para generar HTML (puede tener mejor formato)
                     # Si tu DataManager tiene un método para convertir DF a HTML:
                     # data_head_html = data_manager._get_dataframe_head_html(preview_df[available_and_ordered_preview_cols])
                     # Si no, generar manualmente:
                     data_head_html = preview_df[available_and_ordered_preview_cols].to_html(classes=['data-table', 'table-sm'], border=0, index=False, float_format='%.4f') # Formatear flotantes
                     print("DEBUG: HTML vista previa última detección generado con columnas requeridas y ordenadas.")
                else:
                    # Fallback si no hay columnas comunes
                    print("WARN: Columnas requeridas para vista previa de última detección no encontradas. Generando con columnas disponibles.")
                    data_head_html = preview_df.to_html(classes=['data-table', 'table-sm'], border=0, index=False, float_format='%.4f')
                    print("DEBUG: HTML vista previa última detección generado con todas las columnas disponibles.")

            except Exception as e:
                print(f"ERROR generando HTML para vista previa de datos de la última detección (desde sesión): {e}\n{traceback.format_exc()}")
                data_head_html = "<p>Error al cargar vista previa de datos de la última detección.</p>"
        else:
             data_head_html = "<p>No hay resultados de detección previos para mostrar la vista previa.</p>"
             # No loguear si es la primera carga de la página y no hay resultados previos
             # print("DEBUG: No hay last_detection_results o data_head en sesión.")


        # --- Verificar disponibilidad de datos para el formulario (para mostrar en el template GET) ---
        print("DEBUG: Verificando disponibilidad de datos para el formulario GET.")
        # --- USAR INFO DE LA SESIÓN PARA VERIFICAR DISPONIBILIDAD DE SIMULACIÓN ---
        # Usamos la clave 'simulation_info' que es la que usa la ruta /simulate POST
        sim_info_from_session = session.get('simulation_info') # <<-- USAR 'simulation_info'
        has_simulation_file = sim_info_from_session and sim_info_from_session.get('filepath') and os.path.exists(sim_info_from_session['filepath'])
        print(f"DEBUG: Archivo simulación disponible (según sesión): {has_simulation_file}")

        processed_data_obj = data_manager.get_processed_data()
        has_processed = processed_data_obj is not None and not processed_data_obj.empty
        print(f"DEBUG: Datos preprocesados disponibles: {has_processed}")


    except Exception as e:
        print(f"ERROR general en GET /detect: {e}\n{traceback.format_exc()}")
        flash("Error preparando página de detección.", "danger")
        # Asegurar que las variables críticas tengan valores por defecto en caso de error
        current_model_metrics = None
        cm_plot_url = None
        report_df_html = "<p>Error al cargar el reporte de clasificación.</p>"
        data_head_html = "<p>Error al cargar la vista previa de datos.</p>"
        has_processed = False
        has_simulation_file = False
        # detection_history ya se obtuvo al inicio, detector se asume global


    # --- RETURN FINAL ---
    print("DEBUG: Renderizando template detection.html...")
    return render_template('detection.html',
        has_processed_data=has_processed,
        has_simulation_data=has_simulation_file, # Pasar el resultado de la verificación de sesión
        # Pasamos las métricas de EVALUACIÓN del modelo actual
        current_model_metrics=current_model_metrics,
        report_df=report_df_html, # Pasar el HTML del Reporte de la EVALUACIÓN
        cm_plot_url=cm_plot_url, # Plot CM de la EVALUACIÓN
        # Pasamos la vista previa de datos de la ÚLTIMA detección ejecutada (viene de la sesión)
        last_results=last_detection_results_from_session, # Pasar el diccionario completo de la sesión
        data_head_html=data_head_html, # Pasar el HTML generado del head
        detection_history=detection_history, # Historial de todas las detecciones guardadas
        detector=detector # Para acceder al umbral si es necesario en la plantilla (aunque ya está en historial)
        # Nota: last_results en detection.html debe obtenerse de last_detection_results_from_session directamente en la plantilla
    )

# ... (resto de importaciones y otras rutas) ...

@app.route('/alerts', methods=['GET', 'POST'])
@login_required
def alerts():
    # Determinar la URL de redirección al principio es útil
    redirect_url = url_for('alerts', show_all=request.args.get('show_all', 'false'))

    if request.method == 'POST':
        action = request.form.get('action') # Obtener la acción del formulario

        try:
            # === MANEJAR LA NUEVA ACCIÓN 'delete_all' ===
            if action == 'delete_all':
                print("INFO: Solicitud para borrar todas las alertas recibida.")
                # Suponiendo que tu alert_manager tiene un método delete_all_alerts()
                # Este método debería devolver (True/False, mensaje)
                success, message = alert_manager.delete_all_alerts()
                flash(message, 'success' if success else 'error')
            # === FIN MANEJO 'delete_all' ===

            # === LÓGICA EXISTENTE (Marcar como revisada) ===
            # Si la acción no es 'delete_all', asumimos que es marcar una alerta.
            # Verificamos si se envió 'alert_id'.
            else:
                alert_id_str = request.form.get('alert_id')
                if alert_id_str:
                    alert_id = int(alert_id_str) # Puede lanzar ValueError
                    success_mark = alert_manager.mark_alert_reviewed(alert_id)
                    flash(f"Alerta {alert_id} marcada como revisada.", 'success') if success_mark else flash(f"No se pudo marcar la alerta {alert_id}.", 'warning')
                else:
                    # Si no es 'delete_all' y no hay 'alert_id', es una solicitud POST inesperada
                    flash("Acción desconocida o ID de alerta faltante.", 'warning')
            # === FIN LÓGICA EXISTENTE ===

        except ValueError:
             # Este error solo ocurriría al intentar convertir alert_id_str a int
            flash("ID de alerta inválido.", 'error')
        except Exception as e:
            flash(f"Error procesando la solicitud: {e}", "error")
            print(f"ERROR alerts POST: {e}\n{traceback.format_exc()}")

        # Redirigir siempre después de procesar el POST para evitar reenvíos
        return redirect(redirect_url)

    # --- Solicitud GET (sin cambios) ---
    try:
        show_all = request.args.get('show_all', 'false').lower() == 'true'
        current_alerts = alert_manager.get_alerts(show_all) # Obtener alertas (activas o todas)
    except Exception as e:
        print(f"ERROR alerts GET: {e}\n{traceback.format_exc()}")
        flash("Error al obtener las alertas.", "error")
        current_alerts, show_all = [], False # Valores seguros en caso de error

    return render_template('alerts.html', alerts=current_alerts, show_all=show_all)

@app.route('/admin')
@login_required
def admin_landing():
    if not current_user.is_admin: flash("No tienes permisos.", "error"); return redirect(url_for('dashboard'))
    try: system_config = admin_manager.get_config(); alert_config = alert_manager.config; system_logs = admin_manager.get_system_logs()
    except Exception as e: print(f"ERROR admin GET: {e}\n{traceback.format_exc()}"); flash("Error cargar datos admin.", "error"); system_config, alert_config, system_logs = {}, {}, "Err logs."
    alert_severity_levels = ['Baja', 'Media', 'Alta', 'Crítica']
    return render_template('admin.html', system_config=system_config, alert_config=alert_config, alert_severity_levels=alert_severity_levels, system_logs=system_logs)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
# @admin_required  # Opcional: si solo los administradores pueden cambiar la configuración
def settings():
    print(f"DEBUG: Accediendo a ruta /settings con método {request.method}")

    global system_config, detector, alert_manager

    if request.method == 'POST':
        print("DEBUG: Procesando solicitud POST para /settings")
        try:
            # --- Actualizar configuración del sistema y del detector ---
            new_glm_threshold_str = request.form.get('glm_threshold')

            if new_glm_threshold_str:
                try:
                    new_glm_threshold = float(new_glm_threshold_str)
                    if 0.0 <= new_glm_threshold <= 1.0:
                        system_config['glm_threshold'] = new_glm_threshold
                        if 'detector' in globals() and detector is not None:
                            detector.prediction_threshold = new_glm_threshold
                            print(f"INFO: Umbral del detector actualizado a {new_glm_threshold}.")
                        else:
                            print("WARN: Instancia de detector no disponible para actualizar el umbral.")
                        flash(f"Umbral del modelo actualizado a {new_glm_threshold:.2f}.", "success")
                        print(f"INFO: Umbral del modelo actualizado a {new_glm_threshold}.")
                    else:
                        flash("Error: El umbral del modelo debe estar entre 0.0 y 1.0.", "warning")
                        print(f"WARN: Intento de actualizar umbral con valor fuera de rango: {new_glm_threshold}")
                except ValueError:
                    flash("Error: El umbral del modelo debe ser un número válido.", "warning")
                    print(f"WARN: Intento de actualizar umbral con valor no numérico: {new_glm_threshold_str}")

            # --- Actualizar configuración de alertas ---
            new_severity_threshold = request.form.get('severity_threshold')
            new_notify_email = request.form.get('notify_email') == 'on'

            if 'alert_manager' in globals() and alert_manager is not None:
                alert_manager.update_config(severity_threshold=new_severity_threshold, notify_email=new_notify_email)
                print("INFO: Configuración de alertas procesada.")
            else:
                print("WARN: Instancia de AlertManager no disponible para procesar configuración de alertas.")

            return redirect(url_for('settings'))

        except Exception as e:
            print(f"ERROR procesando solicitud POST para /settings: {e}\n{traceback.format_exc()}")
            flash("Error interno al guardar configuración.", "danger")
            return redirect(url_for('settings'))

    try:
        print("DEBUG: Procesando solicitud GET para /settings")
        current_glm_threshold = system_config.get('glm_threshold', 0.7)
        print(f"DEBUG: Umbral actual para vista GET: {current_glm_threshold}")

        current_severity_threshold = 'Media'
        current_notify_email = False

        if 'alert_manager' in globals() and alert_manager is not None:
            current_severity_threshold = alert_manager.config.get('severity_threshold', 'Media')
            current_notify_email = alert_manager.config.get('notify_email', False)
            print(f"DEBUG: Config alertas para vista GET: Severidad={current_severity_threshold}, Email={current_notify_email}")
        else:
            print("WARN: Instancia de AlertManager no disponible para obtener config de alertas en GET.")

        return render_template('settings.html',
                               title='Configuración',
                               glm_threshold=current_glm_threshold,
                               severity_threshold=current_severity_threshold,
                               notify_email=current_notify_email,
                               alert_severity_levels=['Baja', 'Media', 'Alta', 'Crítica']
                               )
    except Exception as e:
        print(f"ERROR preparando página de configuración GET: {e}\n{traceback.format_exc()}")
        flash("Error al cargar la página de configuración.", "danger")
        return render_template('settings.html',
                               title='Configuración',
                               glm_threshold=system_config.get('glm_threshold', 0.7),
                               severity_threshold='Media',
                               notify_email=False,
                               alert_severity_levels=['Baja', 'Media', 'Alta', 'Crítica']
                               )


@app.route('/admin/action', methods=['POST'])
@login_required
def admin_actions():
    if not current_user.is_admin: flash("Acción no autorizada.", "error"); return redirect(url_for('dashboard'))
    action = request.form.get('action')
    try:
        if action == 'update_threshold': new_threshold = float(request.form.get('glm_threshold')); success, message = admin_manager.update_glm_threshold(new_threshold); flash(message, 'success' if success else 'error')
        elif action == 'update_alert_config': severity = request.form.get('alert_severity_threshold'); notify = 'notify_email' in request.form; success = alert_manager.update_config(severity_threshold=severity, notify_email=notify); flash("Config. alertas actualizada.", "success") if success else flash("No se pudo actualizar.", "warning")
        elif action == 'go_to_user_list': return redirect(url_for('list_users')) # Asegúrate que este link exista en admin.html si lo necesitas
        elif action == 'retrain':
            print("INFO: Recibida solicitud de reentrenamiento REAL.") # Mensaje para confirmar
            # Obtener el DataFrame completo y limpio (con posibles NaNs) de DataManager
            # DataManager.get_processed_data() retorna el DF después de limpieza inicial, Inf->NaN, elim columna/duplicados.
            df_full_cleaned_data = data_manager.get_processed_data() # <-- Usamos este método

            if df_full_cleaned_data is not None and not df_full_cleaned_data.empty:
                print(f"INFO: Dataset completo ({len(df_full_cleaned_data)} filas) obtenido de DataManager para reentrenamiento.")
                # Llamar al método de entrenamiento en el detector
                # train_and_save_model realizará el escalado y la eliminación final de NaNs después del split
                success, message = detector.train_and_save_model(df_full_cleaned_data, sample_fraction_train=0.05) # Ajusta sample_fraction_train si lo necesitas
                flash(message, 'success' if success else 'danger')
                # Después de un entrenamiento exitoso, evaluate_on_test_set() debería funcionar
                # No es necesario llamar a _load_model_components() aquí,
                # train_and_save_model ya actualiza self.model, self.scaler, etc.

            else:
                flash("Error: No hay datos completos y limpios disponibles en DataManager para reentrenar.", 'warning')
                print("WARN: Datos completos no disponibles en DataManager para reentrenamiento.")

        else: flash(f"Acción admin '{action}' desconocida.", 'warning')
    except ValueError: flash("Valor numérico inválido.", 'error')
    except Exception as e: flash(f"Error acción admin: {e}", "error"); print(f"ERROR admin POST: {e}\n{traceback.format_exc()}")
    return redirect(url_for('admin_landing'))

@app.route('/admin/users')
@login_required
@admin_required 
def list_users():
    if not current_user.is_admin: flash("No tienes permisos.", "error"); return redirect(url_for('dashboard'))
    try: all_users = User.query.order_by(User.username).all()
    except Exception as e: print(f"Error obteniendo usuarios: {e}\n{traceback.format_exc()}"); flash("Error al cargar usuarios.", "error"); all_users = []
    return render_template('users_list.html', users=all_users)

@app.route('/users/manage') # Ruta placeholder usuarios
@login_required # Proteger también por si acaso
def manage_users_placeholder():
    # Quizás añadir chequeo de admin aquí también
    # if not current_user.is_admin: return redirect(url_for('dashboard'))
    flash("La gestión de usuarios aún no está implementada.", "info")
    return render_template('users_placeholder.html')


# --- RUTAS DE GESTIÓN DE USUARIOS (Admin) ---




@app.route('/admin/users/new', methods=['GET', 'POST'])
@login_required
@admin_required # Solo admins pueden crear usuarios
def create_user():
    """Página para crear un nuevo usuario (solo admin)."""
    form = UserAdminForm() # Usamos el formulario admin
    if form.validate_on_submit():
        try:
            # Verificar si el username o email ya existen (aunque el form ya lo hace, es una capa extra)
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user:
                 flash('Nombre de usuario ya existe.', 'danger')
                 return render_template('user_form.html', title='Crear Usuario', form=form)

            existing_email = User.query.filter_by(email=form.email.data).first()
            if existing_email:
                 flash('Email ya registrado.', 'danger')
                 return render_template('user_form.html', title='Crear Usuario', form=form)

            new_user = User(username=form.username.data,
                            email=form.email.data,
                            is_admin=form.is_admin.data)
            # La contraseña es obligatoria al crear
            if form.password.data:
                 new_user.set_password(form.password.data)
            else:
                 flash("La contraseña es obligatoria para crear un nuevo usuario.", "danger")
                 return render_template('user_form.html', title='Crear Usuario', form=form) # Volver a mostrar el form

            db.session.add(new_user)
            db.session.commit()
            flash(f'Usuario "{new_user.username}" creado exitosamente.', 'success')
            print(f"INFO: Admin {current_user.username} creó usuario {new_user.username}.")
            return redirect(url_for('list_users')) # Redirigir a la lista
        except Exception as e:
            db.session.rollback() # Revertir cambios en caso de error
            flash(f'Error creando usuario: {e}', 'danger')
            print(f"ERROR creando usuario admin: {e}\n{traceback.format_exc()}")

    # Si es GET o el formulario no validó
    return render_template('user_form.html', title='Crear Usuario', form=form)


@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required # Solo admins pueden editar usuarios
def edit_user(user_id):
    """Página para editar un usuario existente (solo admin)."""
    user = User.query.get_or_404(user_id) # Obtener el usuario por ID, o mostrar 404

    # Pre-llenar el formulario con los datos actuales del usuario para GET
    # Usamos el formulario base con los originales para la validación de unicidad
    form = UserAdminForm(original_username=user.username, original_email=user.email)

    if form.validate_on_submit():
        try:
            # Actualizar datos del usuario
            user.username = form.username.data
            user.email = form.email.data
            user.is_admin = form.is_admin.data

            # Solo cambiar la contraseña si se proporcionó una nueva
            if form.password.data:
                 user.set_password(form.password.data)
                 flash('Contraseña de usuario actualizada.', 'info') # Notificar que la contraseña fue cambiada

            db.session.commit()
            flash(f'Usuario "{user.username}" actualizado exitosamente.', 'success')
            print(f"INFO: Admin {current_user.username} editó usuario {user.username} (ID: {user.id}).")
            return redirect(url_for('list_users')) # Redirigir a la lista
        except Exception as e:
            db.session.rollback() # Revertir cambios
            flash(f'Error actualizando usuario: {e}', 'danger')
            print(f"ERROR editando usuario admin {user_id}: {e}\n{traceback.format_exc()}")

    # Si es GET, pre-llenar el formulario para mostrar
    elif request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
        form.is_admin.data = user.is_admin
        # No pre-llenamos el campo de contraseña por seguridad

    # Renderizar la misma plantilla de formulario, pero para edición
    return render_template('user_form.html', title=f'Editar Usuario: {user.username}', form=form, user=user)


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required # Solo admins pueden eliminar
def delete_user(user_id):
    """Ruta para eliminar un usuario (solo admin)."""
    user = User.query.get_or_404(user_id) # Obtener usuario a eliminar

    # Opcional: añadir una verificación para no permitir que un admin se elimine a sí mismo
    if user.id == current_user.id:
        flash("No puedes eliminar tu propia cuenta de administrador.", "danger")
        return redirect(url_for('list_users'))

    # Opcional: Puedes usar el formulario de confirmación si lo deseas, o simplemente procesar el POST
    # form = DeleteUserForm()
    # if form.validate_on_submit(): # Si usas un formulario con submit
    try:
        db.session.delete(user)
        db.session.commit()
        flash(f'Usuario "{user.username}" eliminado exitosamente.', 'success')
        print(f"INFO: Admin {current_user.username} eliminó usuario {user.username} (ID: {user.id}).")
    except Exception as e:
        db.session.rollback() # Revertir cambios
        flash(f'Error eliminando usuario "{user.username}": {e}', 'danger')
        print(f"ERROR eliminando usuario admin {user_id}: {e}\n{traceback.format_exc()}")

    # Siempre redirigir a la lista de usuarios después de la operación
    return redirect(url_for('list_users'))

# --- Ejecución ---
if __name__ == '__main__':
    # Usar el contexto de la aplicación para operaciones de BD al inicio
    with app.app_context():
        print("INFO: Creando tablas BD si no existen...");
        time_start = datetime.datetime.now()
        # --- Bloque try/except externo para la conexión/creación inicial ---
        try:
            # Intentar crear todas las tablas definidas en los modelos
            db.create_all()
            print(f"INFO: Tablas verificadas/creadas ({(datetime.datetime.now() - time_start).total_seconds():.2f}s).")

            # Comprobar si ya existen usuarios para no intentar crear el admin de nuevo
            if User.query.count() == 0:
                print("INFO: No existen usuarios. Creando usuario admin inicial...")
                # --- Bloque try/except interno para la creación del admin ---
                try:
                    admin_user = User(username='admin', email='admin@example.com', is_admin=True)
                    admin_user.set_password('password') # ¡CAMBIAR ESTA CONTRASEÑA POR DEFECTO!
                    db.session.add(admin_user)
                    db.session.commit()
                    print("INFO: Usuario 'admin' creado / pass: 'password'. ¡POR FAVOR CAMBIARLA!")
                # Manejar error específico al crear el admin
                except Exception as e_admin:
                    db.session.rollback() # Revertir si falla la creación del admin
                    print(f"ERROR: No se pudo crear usuario admin inicial: {e_admin}")
                # --- Fin try/except interno ---

        # Manejar error general de conexión o creación de tablas
        except Exception as e_db:
            print(f"ERROR: No se pudo conectar o crear tablas en la BD: {e_db}")
            print("Verifica la configuración deSQLALCHEMY_DATABASE_URI y que el servidor MySQL esté corriendo.")
            exit() # Salir si no se puede inicializar la BD
        # --- Fin try/except externo ---

    # Iniciar el servidor Flask (fuera del with app.app_context() para la creación inicial)
    print("INFO: Iniciando servidor Flask...")
    # Cambiar debug=False para producción
    app.run(host='0.0.0.0', port=5000, debug=True)