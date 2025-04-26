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
# Usar bcrypt directamente es más seguro que depender solo de Werkzeug para hash
import bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
# --- FIN IMPORTACIONES LOGIN Y BD ---
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, make_response, send_file
from werkzeug.utils import secure_filename
# Importar urlparse desde urllib.parse
from urllib.parse import urlparse
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
    print(f"FATAL ERROR: No se pudo importar clase manager: {e}")
    exit()
from functools import wraps

print("DEBUG: Definiendo decorador admin_required...")
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Acceso no autorizado. Solo para administradores.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# --- Configuración de la App ---
print("DEBUG: Creando instancia de Flask app...")
app = Flask(__name__)
print("DEBUG: Instancia Flask creada.")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "d3v3l0pm3nt_s3cr3t_k3y_pl34s3_ch4ng3_v4")

# Carpetas
UPLOAD_FOLDER = 'uploads'
TEMP_SIM_FOLDER = 'temp_sim_data'
SAVED_PLOTS_FOLDER = 'saved_plots'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TEMP_SIM_FOLDER'] = TEMP_SIM_FOLDER
app.config['SAVED_PLOTS_FOLDER'] = SAVED_PLOTS_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'csv'}
print(f"DEBUG: Carpetas configuradas: UPLOAD={app.config['UPLOAD_FOLDER']}, TEMP_SIM={app.config['TEMP_SIM_FOLDER']}, PLOTS={app.config['SAVED_PLOTS_FOLDER']}")

# --- CONFIGURACIÓN DE BASE DE DATOS ---
DB_USER = "root"
DB_PASS = "" # Ajusta si tienes contraseña
DB_HOST = "localhost"
DB_NAME = "cyber_db"
db_uri = f'mysql+mysqlconnector://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}'
print(f"DEBUG: Configurando URI de BD: {db_uri[:db_uri.find('@')+1]}********")
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False

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
    login_manager.login_view = 'login'
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
system_config = {'glm_threshold': 0.7} # Configuración global

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

try:
    print("DEBUG: Inicializando Managers...")
    data_manager = DataManager()
    simulator = ThreatSimulator()
    alert_manager = AlertManager()
    detector = ThreatDetector()
    admin_manager = AdminManager(detector_instance=detector)
    print("DEBUG: Managers inicializados.")
except Exception as e:
    print(f"FATAL ERROR inicializando manager: {e}\n{traceback.format_exc()}")
    exit()

# --- MODELO DE BASE DE DATOS (USUARIO) ---
print("DEBUG: Definiendo modelo User...")
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def set_password(self, password):
        try:
            password_bytes = password.encode('utf-8')
            salt = bcrypt.gensalt()
            self.password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
        except Exception as e:
            print(f"ERR hash pass: {e}")
            raise ValueError("Error hashear pass") from e

    def check_password(self, password):
        if not self.password_hash:
            print(f"WARN: check_pass sin hash user {self.id}")
            return False
        try:
            password_bytes = password.encode('utf-8')
            stored_hash_bytes = self.password_hash.encode('utf-8')
            return bcrypt.checkpw(password_bytes, stored_hash_bytes)
        except ValueError as ve:
            print(f"ERR (ValueError) check pass user {self.id}: {ve}. Hash inválido?")
            return False
        except Exception as e:
            print(f"ERR general check pass user {self.id}: {e}")
            return False

    def __repr__(self):
        return f'<User {self.username}>'
print("DEBUG: Modelo User definido.")

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    try:
        user = db.session.get(User, int(user_id)) # Usar método moderno
        return user
    except Exception as e:
        print(f"Error cargando user_id {user_id}: {e}")
        return None

# --- FORMULARIOS (Flask-WTF) ---
print("DEBUG: Definiendo Formularios...")
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
        # Usar query para buscar si existe (método válido)
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Usuario ya existe.')
    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Email ya registrado.')
print("DEBUG: Formularios Login/Registration definidos.")

class UserAdminForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña (dejar vacío para no cambiar)')
    is_admin = BooleanField('Es Administrador')
    submit = SubmitField('Guardar Usuario')

    def __init__(self, original_username=None, original_email=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email

    def validate_username(self, username):
        if username.data != self.original_username:
            if User.query.filter_by(username=username.data).first():
                raise ValidationError('Usuario ya existe.')
    def validate_email(self, email):
        if email.data != self.original_email:
            if User.query.filter_by(email=email.data).first():
                raise ValidationError('Email ya registrado.')

class DeleteUserForm(FlaskForm):
    submit = SubmitField('Eliminar Usuario')
print("DEBUG: Formularios Admin definidos.")

# --- Context Processor ---
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.datetime.now().year, 'now': datetime.datetime.now}

# --- Filtro Jinja2 para Fechas ---
@app.template_filter('format_datetime')
def format_datetime_filter(iso_string, format='%Y-%m-%d %H:%M:%S'):
    if not iso_string:
        return "N/A"
    try:
        dt = datetime.datetime.fromisoformat(iso_string)
        return dt.strftime(format)
    except (ValueError, TypeError):
        try:
            dt = datetime.datetime.strptime(iso_string, '%Y-%m-%d %H:%M:%S')
            return dt.strftime(format)
        except (ValueError, TypeError): # Ser más específico en la captura
            print(f"WARN: format_dt no pudo parsear: {iso_string}")
            return iso_string

# --- Funciones de Reporte ---
print("DEBUG: Definiendo funciones de reporte...")
def generate_last_detection_csv(results):
    if not results:
        return None
    output = io.StringIO()
    output.write(f"Reporte Última Detección\nTimestamp: {results.get('ts', 'N/A')}\nFuente: {results.get('src', 'N/A')}\nFilas: {results.get('rows', 'N/A')}\nUmbral: {results.get('thr', 'N/A')}\n\n")
    metrics = results.get('metrics', {})
    if metrics:
        output.write("Métricas Modelo:\n")
        simple = {k: v for k, v in metrics.items() if not isinstance(v, (dict, list, np.ndarray))}
        for n, v in simple.items():
            output.write(f"{n.replace('_', ' ').title()},{v}\n")
        report = metrics.get('report', {})
        if report and isinstance(report, dict):
            output.write("\nReporte Clasificación:\n")
            try:
                pd.DataFrame(report).transpose().to_csv(output, index=True, header=True)
            except Exception as e:
                output.write(f"Err reporte CSV: {e}\n")
        cm = metrics.get('confusion_matrix')
        if cm is not None:
            output.write("\nMatriz Confusión:\n")
            try:
                cm_arr = np.array(cm)
                classes = metrics.get('classes', ['BENIGN', 'ATTACK'])
                output.write("," + ",".join([f"Pred {c}" for c in classes]) + "\n")
                for i, r in enumerate(cm_arr):
                    output.write(f"Real {classes[i]}," + ",".join(map(str, r)) + "\n")
            except Exception as e:
                output.write(f"Err CM CSV: {e}\n")
    summary = results.get('summary', {})
    if summary:
        output.write("\nResumen Detecciones:\nEtiqueta,Cantidad\n")
        for l, c in summary.items():
             output.write(f"{l},{c}\n") # Separar comandos
    head = results.get('head', [])
    if head:
        output.write("\nVista Previa Resultados:\n")
        try:
            pd.DataFrame(head).to_csv(output, index=False)
        except Exception as e:
            output.write(f"Err head CSV: {e}\n")
    output.seek(0)
    return output.getvalue()
print("DEBUG: Funciones reporte OK.")

# --- Helper para Gráficos ---
print("DEBUG: Definiendo funciones gráficos...")
def generate_plot_base64(plot_func, *args, **kwargs):
    img = io.BytesIO()
    fig = None
    try:
        fig = plt.figure(figsize=kwargs.pop('figsize', (6, 5)))
        plot_func(fig=fig, *args, **kwargs)
        plt.savefig(img, format='png', bbox_inches='tight')
        img.seek(0)
        url = base64.b64encode(img.getvalue()).decode('utf8')
        return f"data:image/png;base64,{url}"
    except Exception as e:
        print(f"ERR plot base64: {e}")
        return None
    finally:
        if fig:
            plt.close(fig)

def plot_and_save_confusion_matrix_func(cm, fig, classes=None, title='Matriz Confusión', save_plot=False, save_dir=None):
    if classes is None:
        classes = ['BENIGN', 'ATTACK']
    try:
        ax = fig.add_subplot(111)
        cm_arr = np.array(cm)
        sns.heatmap(cm_arr, annot=True, fmt='d', cmap='Blues', ax=ax, cbar=False, xticklabels=classes, yticklabels=classes)
        ax.set_xlabel('Predicción')
        ax.set_ylabel('Real')
        ax.set_title(title)
        plt.tight_layout()
        if save_plot:
            if not save_dir:
                print("ERR plot_cm: save_dir necesario.")
                return
            os.makedirs(save_dir, exist_ok=True)
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = f"cm_{ts}.png"
            fp = os.path.join(save_dir, fname)
            try:
                fig.savefig(fp, bbox_inches='tight')
                print(f"INFO: CM guardada: {fp}")
            except Exception as e_save:
                print(f"ERR guardar CM: {e_save}")
    except Exception as e:
        print(f"ERR plot_cm: {e}")
        ax = fig.add_subplot(111) # Asegurarse que ax existe
        ax.text(0.5, 0.5, f'Err plot:\n{e}', ha='center', va='center', color='red', fontsize=10)
        plt.tight_layout() # Ajustar layout incluso con error
print("DEBUG: Funciones gráficos OK.")

# --- RUTAS AUTENTICACIÓN ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            flash(f'Login OK para {user.username}!', 'success')
            next_page = request.args.get('next')
            if next_page and urlparse(next_page).netloc == '':
                print(f"DEBUG: Redirect next: {next_page}")
                return redirect(next_page)
            else:
                print("DEBUG: Redirect dashboard.")
                return redirect(url_for('dashboard'))
        else:
            flash('Login fallido.', 'error')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada.', 'info')
    print("INFO: User logout.")
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
            user.is_admin = User.query.count() == 0
            db.session.add(user)
            db.session.commit()
            flash(f'Cuenta creada {form.username.data}! Inicia sesión.', 'success')
            print(f"INFO: Nuevo user: {form.username.data}{' (admin)' if user.is_admin else ''}")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            err = str(e)
            if 'Duplicate entry' in err:
                 if 'users.username' in err:
                     flash('Err: Usuario ya existe.', 'error')
                 elif 'users.email' in err:
                     flash('Err: Email ya registrado.', 'error')
                 else:
                     flash(f'Err duplicado BD: {err}', 'error')
            else:
                flash(f'Err crear cuenta: {err}', 'error')
            print(f"ERR /register POST: {e}")
    return render_template('register.html', title='Registro', form=form)

# --- RUTAS PRINCIPALES ---
@app.route('/')
@login_required
def dashboard():
    try:
        active = alert_manager.get_alerts(show_all=False)
        all_sorted = alert_manager.get_alerts(show_all=True)
        recent = all_sorted[:5]
        history = alert_manager.get_detection_history()
        last = history[-1] if history else None
        model_stat = "Real" if detector and detector.model else "Simulado"
    except Exception as e:
        print(f"ERR dashboard data: {e}")
        flash("Err cargar dashboard.", "error")
        active, last, model_stat, recent = [], None, "Error", []
    return render_template('dashboard.html', active_alerts_count=len(active), last_detection=last, model_status=model_stat, recent_alerts=recent)

@app.route('/data', methods=['GET', 'POST'])
@login_required
def manage_data():
    if request.method == 'POST':
        action = request.form.get('action')
        url = url_for('manage_data')
        try:
            if action == 'upload':
                if 'file' not in request.files:
                    flash('No file part.', 'error')
                    return redirect(url)
                file = request.files['file']
                fname = file.filename
                if fname == '':
                    flash('No selected file.', 'warning')
                    return redirect(url)
                if file and allowed_file(fname):
                    fname = secure_filename(fname)
                    fpath = os.path.join(app.config['UPLOAD_FOLDER'], fname)
                    file.save(fpath)
                    ok, msg = data_manager.load_csv_data(fpath)
                    if ok:
                        flash(msg, 'success')
                        session['loaded_filepath'] = fpath
                        session.pop('processed_data_info', None)
                    else:
                        flash(msg, 'error')
                        session.pop('loaded_filepath', None)
                elif file:
                    flash(f"Tipo no permitido.", 'error')
            elif action == 'preprocess':
                if data_manager.loaded_data is not None:
                    ok, msg = data_manager.preprocess_data()
                    if ok:
                        flash(msg, 'success')
                        session['processed_data_info'] = {
                            'rows': len(data_manager.processed_data) if data_manager.processed_data is not None else 0,
                            'cols': len(data_manager.processed_data.columns) if data_manager.processed_data is not None else 0,
                            'ts': datetime.datetime.now().isoformat(timespec='seconds')
                        }
                    else:
                        flash(msg, 'error')
                        session.pop('processed_data_info', None)
                else:
                    flash('Carga CSV primero.', 'warning')
            else:
                flash('Acción desconocida.', 'warning')
        except Exception as e:
            flash(f"Err gestión datos: {e}", "error")
            print(f"ERR manage_data POST: {e}")
            session.pop('loaded_filepath', None)
            session.pop('processed_data_info', None)
        return redirect(url)
    # GET
    try:
        l_head = data_manager.get_loaded_data_head_html()
        p_head = data_manager.get_processed_data_head_html()
        p_info = session.get('processed_data_info')
        l_path = session.get('loaded_filepath')
        l_fname = os.path.basename(l_path) if l_path and os.path.exists(l_path) else None
    except Exception as e:
        print(f"ERR manage_data GET: {e}")
        flash("Err vistas previas.", "error")
        l_head, p_head, p_info, l_fname = "<p>Err</p>", "<p>Err</p>", None, None
    return render_template('data_management.html', loaded_head_html=l_head, processed_head_html=p_head, loaded_filename=l_fname, processed_info=p_info)

@app.route('/simulate', methods=['GET', 'POST'])
@login_required
def simulate():
    if request.method == 'POST':
        try:
            dur = int(request.form.get('duration', 60))
            intensity = int(request.form.get('intensity', 5))
            # Asegurar que request.form.getlist('attacks') devuelve una lista iterable
            attacks_raw = request.form.getlist('attacks')
            attacks = [a.strip() for a in attacks_raw if a.strip()] or ['Attack']

            if dur <= 0:
                  raise ValueError("Duración debe ser mayor a 0.")
            if not (1 <= intensity <= 10):
                  raise ValueError("Intensidad debe estar entre 1 y 10.")
            cfg = {"duration": dur, "intensity": intensity, "attacks": attacks}
            print(f"INFO: Solicitud sim: {cfg}")

            # Ejecutar la simulación
            df = simulator.run_simulation(cfg)

            # Procesar resultados si la simulación generó datos válidos
            if df is not None and not df.empty:
                sim_id = str(uuid.uuid4())
                fname = f"sim_{sim_id}.pkl"
                fpath = os.path.join(app.config['TEMP_SIM_FOLDER'], fname)

                try:
                    # Guardar el DataFrame completo en un archivo temporal
                    df.to_pickle(fpath)
                    print(f"INFO: Sim guardada: {fpath}")

                    # Guardar la metadata de la simulación y la ruta del archivo en la sesión
                    session['simulation_info'] = {
                        'rows_generated': len(df),
                        'config': cfg,
                        'timestamp': datetime.datetime.now().isoformat(timespec='seconds'),
                        'filepath': fpath
                    }
                    session['simulation_ran'] = True # Marcar que se intentó simular (y generó datos)
                    flash(f'Simulación completada. Generados {len(df)} registros.', 'success')

                    # Opcional: Guarda la vista previa HTML directamente si no quieres generarla en el GET
                    # prev_html_from_df = df.head(10).to_html(classes=['data-table', 'table-sm'], border=0, index=False)
                    # session['last_simulation_preview_html_cached'] = prev_html_from_df

                except Exception as e_save:
                    # Limpiar sesión si falla el guardado del archivo
                    flash(f"Error al guardar el archivo de simulación: {e_save}", "error")
                    print(f"ERR guardar pickle sim: {e_save}\n{traceback.format_exc()}")
                    session.pop('simulation_info', None)
                    session['simulation_ran'] = False # Falló la generación completa
                    # session.pop('last_simulation_preview_html_cached', None)

            else:
                # La simulación no generó datos
                flash('La simulación no generó datos. Verifica la configuración.', 'warning')
                session.pop('simulation_info', None)
                session['simulation_ran'] = True # Se intentó pero no hubo datos
                # session.pop('last_simulation_preview_html_cached', None)

        except ValueError as ve:
            # Error en los datos de entrada
            flash(f'Entrada inválida para la simulación: {ve}', 'error')
            session['simulation_ran'] = False # No se ejecutó la simulación
        except Exception as e:
            # Otros errores inesperados
            flash(f'Error inesperado durante la simulación: {e}', 'error')
            print(f"ERR simulate POST: {e}\n{traceback.format_exc()}")
            session.pop('simulation_info', None)
            session['simulation_ran'] = False
            # session.pop('last_simulation_preview_html_cached', None)

        # Redirigir siempre al GET después de un POST
        return redirect(url_for('simulate'))

    # --- GET Request ---
    print("DEBUG: Procesando GET /simulate")
    sim_info = None
    history = []
    prev_html = None
    prev_df = None # Variable para el DataFrame de vista previa (solo la cabeza)

    try:
        # Recuperar info de la última simulación y el historial
        sim_info = session.get('simulation_info')
        history = simulator.get_history() # Asegúrate de que get_history carga la info correcta

        # --- Cargar la vista previa del DataFrame desde el archivo guardado ---
        if sim_info and sim_info.get('filepath') and os.path.exists(sim_info['filepath']):
             try:
                 print(f"DEBUG: Intentando cargar preview desde pickle: {sim_info['filepath']}")
                 # Cargar el DataFrame completo desde el archivo
                 full_df = pd.read_pickle(sim_info['filepath'])

                 if full_df is not None and not full_df.empty:
                     # Tomar solo la cabeza para la vista previa en el template
                     prev_df = full_df.head(10)
                     print(f"DEBUG: DataFrame preview cargado ({len(prev_df)} filas).")

                     # Generar el HTML a partir del DataFrame de vista previa
                     prev_html = prev_df.to_html(classes=['data-table', 'table-sm'], border=0, index=False)
                     print("DEBUG: HTML preview generado.")
                 else:
                     # El archivo existía pero el DataFrame estaba vacío
                     print(f"WARN: Archivo pickle vacío o inválido: {sim_info['filepath']}")
                     prev_html = "<p>El archivo de simulación no contiene datos válidos.</p>"
                     prev_df = None # Asegurar que es None

             except Exception as e_load:
                 # Error al cargar o procesar el archivo pickle
                 print(f"WARN: No se pudo cargar la vista previa de la simulación desde el archivo: {e_load}\n{traceback.format_exc()}")
                 prev_html = f"<p>No se pudo cargar la vista previa de la simulación: {e_load}</p>"
                 prev_df = None # Asegurar que es None


    except Exception as e_get_prep:
        # Error general al preparar los datos para el GET
        print(f"ERR al preparar datos para simulate GET: {e_get_prep}\n{traceback.format_exc()}")
        flash("Error al cargar los datos del simulador.", "error")
        sim_info, history, prev_html, prev_df = None, [], None, None # Asegurar que son None en caso de error

    # Asegurarse de que simulation_ran está disponible en el contexto si la usas en el template
    # Esta bandera indica si se intentó ejecutar una simulación en la ÚLTIMA solicitud POST
    simulation_ran_flag = session.get('simulation_ran', False)
    # Limpiar la bandera 'simulation_ran' de la sesión después de leerla en el GET
    # para que el mensaje solo aparezca justo después de la simulación.
    session.pop('simulation_ran', None)


    # --- Renderizar el template, pasando todas las variables necesarias ---
    return render_template('simulator.html',
                           simulation_history=history, # Historial de simulaciones (metadata)
                           last_simulation_info=sim_info, # Info de la última simulación (metadata + filepath)
                           last_simulation_preview_html=prev_html, # HTML de la vista previa (generado en el GET)
                           last_simulation_preview_df=prev_df, # DataFrame de la vista previa (generado en el GET)
                           simulation_ran=simulation_ran_flag # Bandera para controlar mensajes en el template
                           )

@app.route('/detect', methods=['GET', 'POST'])
@login_required
def detect():
    print(f"DEBUG: /detect {request.method}")
    history = alert_manager.get_detection_history()
    session_res = session.get('last_detection_results')
    head_html, model_metrics, cm_url, report_html, alerts = None, None, None, None, []

    if request.method == 'POST':
        print("DEBUG: POST /detect")
        try:
            ds = request.form.get('datasource')
            print(f"DEBUG: Fuente: {ds}")
            df, src_info, rows_count = None, "N/A", 0

            if ds == 'processed':
                df_proc = data_manager.get_processed_data()
                if df_proc is not None and not df_proc.empty:
                    df = df_proc.copy()
                    src_info = "Datos Preprocesados"
                    rows_count = len(df_proc)
                    print(f"INFO: Detectando {src_info} ({rows_count})")
                else:
                    flash("No datos preproc.", "warning")
                    return redirect(url_for('detect'))
            elif ds == 'simulation':
                sim = session.get('simulation_info')
                if sim and sim.get('filepath') and os.path.exists(sim['filepath']):
                    try:
                        print(f"INFO: Cargando sim {sim['filepath']}")
                        df_sim = pd.read_pickle(sim['filepath'])
                        if df_sim is not None and not df_sim.empty:
                            df = df_sim.copy()
                            src_info = f"Sim ({os.path.basename(sim['filepath'])})"
                            rows_count = len(df_sim)
                            print(f"INFO: Detectando {src_info} ({rows_count})")
                            try:
                                df.columns = df.columns.str.strip().str.replace(r'[^\w]+', '_', regex=True).str.lower().str.strip('_')
                            except Exception as e_cl:
                                print(f"ERR limpiar cols sim: {e_cl}")
                        else:
                            flash("Sim vacía.", "warning")
                            return redirect(url_for('detect'))
                    except Exception as e_ld:
                        print(f"ERR cargar sim: {e_ld}")
                        flash(f"Err cargar sim: {e_ld}", "danger")
                        return redirect(url_for('detect'))
                else:
                    flash("No datos sim.", "warning")
                    return redirect(url_for('detect'))
            else:
                flash("Fuente inválida.", "danger")
                return redirect(url_for('detect'))

            # Ejecutar Detección (Bloque reestructurado)
            final_output = None
            if df is not None and not df.empty:
                temp_output = None
                try:
                    print("INFO: Llamando detector.run_detection()")
                    temp_output = detector.run_detection(df)
                    print("INFO: run_detection completado.")
                    if temp_output is not None and isinstance(temp_output, dict) and 'data' in temp_output:
                        final_output = temp_output
                        print("DEBUG: Formato salida OK.")
                    else:
                        print("ERROR: run_detection formato inválido.")
                        flash("Error interno: formato salida inesperado.", "danger")
                        final_output = None
                except Exception as e_det:
                    print(f"ERROR run_detection: {e_det}\n{traceback.format_exc()}")
                    flash(f"Error detección: {e_det}", "danger")
                    final_output = None
            else:
                 print("WARN: No datos válidos para detector.")

            # Procesar Resultados
            if final_output is not None:
                 df_res = final_output.get('data')
                 if df_res is not None and not df_res.empty:
                    print("DEBUG: Procesando post-detección...")
                    try:
                        results = {
                            'ts': datetime.datetime.now().isoformat(timespec='seconds'),
                            'src': src_info, 'rows': rows_count,
                            'thr': detector.prediction_threshold if detector else None,
                            'metrics': final_output.get('metrics', {}),
                            'summary': final_output.get('detection_summary', {})
                        }
                        prev_cols = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'label', 'prediction_label', 'prediction_proba']
                        avail = [c for c in prev_cols if c in df_res.columns]
                        df_prev = df_res[avail].head(10) if avail else df_res.head(10)
                        results['head'] = df_prev.to_dict('records')
                        if not avail:
                            print("WARN: Cols preview no encontradas.")
                        session['last_detection_results'] = results
                        print("DEBUG: Resultados guardados sesión.")
                        hist = results.copy()
                        hist.pop('head', None)
                        alert_manager.add_detection_to_history(hist)
                        print("INFO: Resumen añadido historial.")
                        if 'prediction_label' in df_res.columns:
                            print(f"INFO: Pasando {len(df_res)} filas a AlertManager...")
                            n_alerts, _ = alert_manager.generate_alerts(df_res)
                            print(f"INFO: {n_alerts} nuevas alertas.")
                            if n_alerts > 0:
                                flash(f"{n_alerts} nuevas alertas.", "info")
                        else:
                            print("WARN: 'prediction_label' no encontrada.")
                            flash("No se pudo generar alertas: col predicción no disponible.", "warning")
                        print("SUCCESS: Post-detección OK.")
                        flash("Detección completada.", "success")
                    except Exception as e_post:
                        print(f"ERR post-detección: {e_post}\n{traceback.format_exc()}")
                        flash(f"Error procesar res/alertas: {e_post}", "danger")
                 else:
                      print("WARN: DataFrame resultados vacío.")
                      flash("Detección sin resultados.", "warning")
        except Exception as e_gen_post:
            print(f"ERR general POST /detect: {e_gen_post}\n{traceback.format_exc()}")
            flash(f"Error interno detección: {e_gen_post}", "danger")
        return redirect(url_for('detect'))

    # GET
    try:
        print("DEBUG: Procesando GET /detect")
        print("DEBUG: Evaluando modelo...")
        eval_metrics = detector.evaluate_on_test_set()
        if eval_metrics and eval_metrics.get('accuracy') is not None:
            model_metrics = eval_metrics
            print("DEBUG: Métricas eval OK.")
            if model_metrics.get('confusion_matrix') is not None:
                try:
                    print("DEBUG: Generando plot CM eval...")
                    cm_url = generate_plot_base64(
                        plot_and_save_confusion_matrix_func,
                        model_metrics['confusion_matrix'],
                        classes=model_metrics.get('classes'),
                        title='Matriz Confusión (Evaluación)',
                        save_plot=True,
                        save_dir=app.config['SAVED_PLOTS_FOLDER']
                    )
                    if cm_url:
                        print("DEBUG: Plot CM eval OK.")
                    else:
                        flash("Error generar gráfica CM.", "warning")
                except Exception as e_cm:
                    print(f"ERR plot CM: {e_cm}")
                    cm_url = None
                    flash("Error generar/guardar CM.", "warning")
            report = model_metrics.get('report')
            if report is not None and isinstance(report, dict):
                 try:
                     df_rep = pd.DataFrame(report).transpose()
                     report_html = df_rep.to_html(classes=['data-table', 'table-sm'], border=0, float_format='%.4f')
                     print("DEBUG: Reporte eval HTML OK.")
                 except Exception as e_rep:
                     print(f"WARN: Falló conversión reporte: {e_rep}")
                     report_html = "<p>Err reporte.</p>"
                     flash("Error procesar reporte.", "warning")
            elif report is not None:
                report_html = f"<p>Reporte no disponible: {report}</p>"
            else:
                report_html = "<p>Reporte clasificación no disponible.</p>"
        else:
            print("INFO: No métricas eval.")
            err = eval_metrics.get('report', 'Eval fallida/no modelo.') if eval_metrics else 'Eval fallida/no modelo.'
            report_html = f"<p>Métricas no disponibles. {err}</p>"

        head_recs = session_res.get('head') if session_res else None
        if head_recs:
            print("DEBUG: Generando HTML preview...")
            try:
                df_h = pd.DataFrame(head_recs)
                prev_cols = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'label', 'prediction_label', 'prediction_proba']
                avail = [c for c in prev_cols if c in df_h.columns]
                if avail:
                    head_html = df_h[avail].to_html(classes=['data-table', 'table-sm'], border=0, index=False, float_format='%.4f')
                else:
                    head_html = df_h.to_html(classes=['data-table', 'table-sm'], border=0, index=False, float_format='%.4f')
                    print("WARN: Cols preview no encontradas.")
                print("DEBUG: HTML preview OK.")
            except Exception as e_h:
                print(f"ERR HTML preview: {e_h}")
                head_html = "<p>Err preview.</p>"
        else:
            head_html = "<p>Aún no se ha ejecutado detección.</p>"

        print("DEBUG: Verificando datos form GET.")
        sim = session.get('simulation_info')
        has_sim = sim and sim.get('filepath') and os.path.exists(sim['filepath'])
        proc = data_manager.get_processed_data()
        has_proc = proc is not None and not proc.empty
        print(f"DEBUG: Datos? Sim: {has_sim}, Proc: {has_proc}")

        print("DEBUG: Obteniendo alertas...")
        try:
            alerts = alert_manager.get_alerts(show_all=False)
            print(f"DEBUG: {len(alerts)} alertas activas.")
        except Exception as e_al:
            print(f"ERR obtener alertas: {e_al}")
            flash("Error cargar alertas.", "error")
            alerts = []
    except Exception as e_get:
        print(f"ERR general GET /detect: {e_get}")
        flash("Error preparar página.", "danger")
        model_metrics, cm_url, report_html, head_html, alerts = None, None, "<p>Err</p>", "<p>Err</p>", []
        has_proc, has_sim = False, False

    print("DEBUG: Renderizando detection.html...")
    return render_template('detection.html',
                           has_processed_data=has_proc,
                           has_simulation_data=has_sim,
                           current_model_metrics=model_metrics,
                           report_df=report_html,
                           cm_plot_url=cm_url,
                           last_results=session_res,
                           data_head_html=head_html,
                           detection_history=history,
                           active_alerts=alerts,
                           detector=detector)


@app.route('/mark_alert_reviewed/<int:alert_id>', methods=['POST'])
@login_required
def mark_alert_reviewed(alert_id):
    print(f"DEBUG: POST /mark_alert_reviewed/{alert_id}")
    try:
        success = alert_manager.mark_alert_reviewed(alert_id)
        if success:
            flash(f"Alerta {alert_id} marcada revisada.", 'success')
            print(f"INFO: Alerta {alert_id} marcada por {current_user.username}.")
        else:
            flash(f"No se marcó alerta {alert_id}.", 'warning')
            print(f"WARN: No se marcó alerta {alert_id}.")
    except Exception as e:
        flash(f"Error marcar alerta {alert_id}: {e}", "error")
        print(f"ERR marcar alerta {alert_id}: {e}")
    return redirect(url_for('detect'))

@app.route('/download_detection_results', methods=['GET'])
@login_required
def download_detection_results():
    flash("Descarga resultados completos no implementada.", "warning")
    print("WARN: /download_detection_results accedida.")
    return redirect(url_for('detect'))

@app.route('/report/last_detection_csv')
@login_required
def download_last_detection_csv():
    print("DEBUG: GET /report/last_detection_csv")
    results = session.get('last_detection_results')
    if not results:
        flash("No resultados recientes.", "warning")
        return redirect(url_for('detect'))
    try:
        csv = generate_last_detection_csv(results)
        if csv is None:
            flash("Error generar reporte CSV.", "error")
            return redirect(url_for('detect'))
        resp = make_response(csv)
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        fname = f"reporte_deteccion_{ts}.csv"
        resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
        resp.headers["Content-type"] = "text/csv; charset=utf-8"
        print(f"INFO: Reporte CSV generado: {fname}")
        return resp
    except Exception as e:
        print(f"ERR generar reporte CSV: {e}")
        flash("Error interno reporte CSV.", "error")
        return redirect(url_for('detect'))

@app.route('/admin')
@login_required
@admin_required
def admin_landing():
    print("DEBUG: GET /admin")
    try:
        sys_conf = admin_manager.get_config()
        alert_conf = alert_manager.config
        logs = admin_manager.get_system_logs()
        sev_levels = alert_manager.get_severity_levels() if hasattr(alert_manager, 'get_severity_levels') else ['Baja', 'Media', 'Alta', 'Crítica']
    except Exception as e:
        print(f"ERR cargar datos admin: {e}")
        flash("Error cargar admin.", "error")
        sys_conf, alert_conf, logs, sev_levels = {}, {}, ["Err logs."], ['Baja', 'Media', 'Alta', 'Crítica']
    # Pasar system_config global para que el form muestre el valor actual
    return render_template('admin.html',
                           system_config=system_config,
                           alert_config=alert_conf,
                           alert_severity_levels=sev_levels,
                           system_logs=logs)

@app.route('/admin/action', methods=['POST'])
@login_required
@admin_required
def admin_actions():
    action = request.form.get('action')
    print(f"INFO: POST /admin/action: {action}")
    try:
        if action == 'update_threshold':
            try:
                thr_str = request.form.get('glm_threshold')
                thr = float(thr_str)
                if 0.0 <= thr <= 1.0:
                    success, msg = admin_manager.update_glm_threshold(thr)
                    flash(msg, 'success' if success else 'error')
                    # Actualizar también el global para consistencia inmediata en settings GET
                    system_config['glm_threshold'] = thr
                else:
                    flash("Umbral fuera rango.", "warning")
            except (ValueError, TypeError):
                flash("Umbral inválido.", 'error')
            except Exception as e_thr:
                flash(f"Err umbral: {e_thr}", "danger")
                print(f"ERR update_thr: {e_thr}")
        elif action == 'update_alert_config':
            sev = request.form.get('alert_severity_threshold')
            notify = request.form.get('notify_email') == 'on'
            success = alert_manager.update_config(severity_threshold=sev, notify_email=notify)
            if success:
                flash("Config. alertas actualizada.", "success")
                print(f"INFO: Config alertas (Sev:{sev}, Email:{notify}) por admin {current_user.username}.")
            else:
                 flash("No se actualizó config. alertas.", "warning")
        elif action == 'retrain':
            print("INFO: Solicitud reentrenamiento.")
            df = data_manager.get_processed_data()
            if df is not None and not df.empty:
                print(f"INFO: Datos ({len(df)} filas) para reentrenar.")
                try:
                    success, msg = detector.train_and_save_model(df, sample_fraction_train=0.1) # Ajustar si es necesario
                    flash(msg, 'success' if success else 'danger')
                except Exception as e_tr:
                    flash(f"Err reentrenamiento: {e_tr}", "danger")
                    print(f"ERR train_save: {e_tr}")
            else:
                flash("No datos preproc para reentrenar.", 'warning')
                print("WARN: Reentrenar sin datos.")
        elif action == 'delete_all_alerts':
             print("INFO: Admin borrar alertas.")
             try:
                 success, msg = alert_manager.delete_all_alerts()
                 flash(msg, 'success' if success else 'error')
             except Exception as e_del:
                 flash(f"Err borrar alertas: {e_del}", "danger")
                 print(f"ERR del_alerts: {e_del}")
        else:
            flash(f"Acción admin desconocida: '{action}'.", 'warning')
            print(f"WARN: Acción admin desconocida: {action}")
    except ValueError:
        flash("Valor numérico inválido.", 'error')
    except Exception as e:
        flash(f"Error acción admin: {e}", "error")
        print(f"ERR admin POST {action}: {e}")
    return redirect(url_for('admin_landing'))

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
    del_form = DeleteUserForm()
    return render_template('users_list.html', users=users, delete_form=del_form)

@app.route('/admin/users/new', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    print(f"DEBUG: /admin/users/new {request.method}")
    form = UserAdminForm()
    if form.validate_on_submit():
        try:
            user = User(username=form.username.data, email=form.email.data, is_admin=form.is_admin.data)
            if form.password.data:
                user.set_password(form.password.data)
            else:
                flash("Pass obligatoria.", "danger")
                return render_template('user_form.html', title='Crear', form=form, is_new=True)
            db.session.add(user)
            db.session.commit()
            flash(f'User "{user.username}" creado.', 'success')
            print(f"INFO: Admin {current_user.username} creó user {user.username}.")
            return redirect(url_for('list_users'))
        except ValidationError as ve:
            flash(f"Validación: {ve}", 'danger')
            print(f"WARN: ValidErr create: {ve}")
        except Exception as e:
            db.session.rollback()
            flash(f'Err crear user: {e}', 'danger')
            print(f"ERR crear user: {e}")
        return render_template('user_form.html', title='Crear', form=form, is_new=True) # Re-render on error
    return render_template('user_form.html', title='Crear', form=form, is_new=True) # Render for GET

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    print(f"DEBUG: /admin/users/{user_id}/edit {request.method}")
    user = User.query.get_or_404(user_id)
    form = UserAdminForm(original_username=user.username, original_email=user.email)
    if form.validate_on_submit():
        try:
            user.username=form.username.data
            user.email=form.email.data
            user.is_admin=form.is_admin.data
            pw = False
            if form.password.data:
                user.set_password(form.password.data)
                pw = True
            db.session.commit()
            flash(f'User "{user.username}" actualizado.' + (' (Pass ok)' if pw else ''), 'success')
            print(f"INFO: Admin {current_user.username} editó user {user.username}. Pass:{pw}.")
            return redirect(url_for('list_users'))
        except ValidationError as ve:
            flash(f"Validación: {ve}", 'danger')
            print(f"WARN: ValidErr edit {user_id}: {ve}")
        except Exception as e:
            db.session.rollback()
            flash(f'Err actualizar user: {e}', 'danger')
            print(f"ERR edit user {user_id}: {e}")
        # Re-render form with current data if validation/commit fails
        return render_template('user_form.html', title=f'Editar: {user.username}', form=form, user=user, is_new=False)
    elif request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
        form.is_admin.data = user.is_admin
    return render_template('user_form.html', title=f'Editar: {user.username}', form=form, user=user, is_new=False)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    print(f"DEBUG: POST /admin/users/{user_id}/delete")
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("No puedes borrarte.", "danger")
        return redirect(url_for('list_users'))
    form = DeleteUserForm()
    if form.validate_on_submit(): # Check CSRF if enabled
        try:
            name = user.username
            db.session.delete(user)
            db.session.commit()
            flash(f'User "{name}" eliminado.', 'success')
            print(f"INFO: Admin {current_user.username} eliminó user {name}.")
        except Exception as e:
            db.session.rollback()
            flash(f'Err eliminar "{user.username}": {e}', 'danger')
            print(f"ERR eliminar user {user_id}: {e}")
    else:
        flash("Err solicitud borrado.", "danger") # CSRF or other form error
    return redirect(url_for('list_users'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    print(f"DEBUG: /settings {request.method}")
    global system_config, detector, alert_manager # Needed if modifying globals
    if request.method == 'POST':
        print("DEBUG: POST /settings")
        try:
            thr_str = request.form.get('glm_threshold')
            if thr_str:
                try:
                    thr = float(thr_str)
                    if 0.0 <= thr <= 1.0:
                        if detector:
                            detector.prediction_threshold = thr
                        system_config['glm_threshold'] = thr # Update global config
                        flash(f"Umbral actualizado a {thr:.2f}.", "success")
                        print(f"INFO: Umbral -> {thr} por {current_user.username}.")
                    else:
                        flash("Umbral fuera rango.", "warning")
                except ValueError:
                    flash("Umbral inválido.", "warning")
            sev = request.form.get('severity_threshold')
            email = request.form.get('notify_email') == 'on'
            if alert_manager:
                if alert_manager.config.get('severity_threshold') != sev or alert_manager.config.get('notify_email') != email:
                    if alert_manager.update_config(severity_threshold=sev, notify_email=email):
                        flash("Config. alertas actualizada.", "success")
                        print(f"INFO: Config alertas (Sev:{sev}, Email:{email}) por {current_user.username}.")
                    else:
                        flash("Err actualizar config. alertas.", "warning")
            else:
                 flash("ERR: Gestor alertas no disponible.", "danger")
            return redirect(url_for('settings'))
        except Exception as e:
            print(f"ERR POST /settings: {e}")
            flash("Err interno guardar config.", "danger")
            return redirect(url_for('settings'))
    # GET
    try:
        print("DEBUG: GET /settings")
        # Read current values for display
        c_thr = detector.prediction_threshold if detector else system_config.get('glm_threshold', 0.7)
        c_sev = alert_manager.config.get('severity_threshold', 'Media') if alert_manager else 'Media'
        c_email = alert_manager.config.get('notify_email', False) if alert_manager else False
        levels = alert_manager.get_severity_levels() if hasattr(alert_manager, 'get_severity_levels') else ['Baja', 'Media', 'Alta', 'Crítica']
        print(f"DEBUG: GET settings vals: Thr={c_thr}, Sev={c_sev}, Email={c_email}")
        return render_template('settings.html',
                               title='Config',
                               glm_threshold=c_thr,
                               severity_threshold=c_sev,
                               notify_email=c_email,
                               alert_severity_levels=levels)
    except Exception as e:
        print(f"ERR GET /settings: {e}")
        flash("Err cargar config.", "danger")
        # Return with safe defaults if error occurs
        return render_template('settings.html',
                               title='Config',
                               glm_threshold=0.7,
                               severity_threshold='Media',
                               notify_email=False,
                               alert_severity_levels=['Baja', 'Media', 'Alta', 'Crítica'])

# --- Ejecución ---
if __name__ == '__main__':
    with app.app_context():
        print("INFO: Verificando/Creando tablas BD...")
        t_start = datetime.datetime.now()
        try:
            db.create_all()
            print(f"INFO: Tablas OK ({(datetime.datetime.now() - t_start).total_seconds():.2f}s).")
            if User.query.count() == 0:
                print("INFO: Creando admin inicial...")
                try:
                    admin = User(username='admin', email='admin@example.com', is_admin=True)
                    admin.set_password('password123') # CAMBIAR ESTA CONTRASEÑA
                    db.session.add(admin)
                    db.session.commit()
                    print("INFO: Admin 'admin'/'password123' creado. ¡CAMBIARLA!")
                except Exception as e_adm:
                    db.session.rollback()
                    print(f"ERR crear admin: {e_adm}")
        except Exception as e_db:
            print(f"FATAL ERR DB: {e_db}\nVerifica config URI y servidor MySQL.")
            exit()
    print("INFO: Iniciando Flask server...")
    app.run(host='0.0.0.0', port=5000, debug=True)