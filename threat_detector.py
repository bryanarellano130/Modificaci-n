# threat_detector.py
import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix, accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler # Usaremos StandardScaler
from sklearn.model_selection import train_test_split
import statsmodels.api as sm
import statsmodels.tools.sm_exceptions
import joblib
import os
import warnings
import traceback
import shutil # Añadido para copiar archivos
from werkzeug.utils import secure_filename # Añadido para limpiar nombres

# Definir el directorio donde se guardarán/cargarán los componentes del modelo
# Usar una ruta relativa al script es más portable
BASE_DIR_DETECTOR = os.path.abspath(os.path.dirname(__file__))
MODEL_DIR = os.path.join(BASE_DIR_DETECTOR, 'models') # Carpeta 'models' junto a threat_detector.py

class ThreatDetector:
    """
    Detecta amenazas usando un modelo de ML entrenado (GLM con muestreo).
    Gestiona el entrenamiento, guardado, carga y predicción del modelo.
    """
    def __init__(self, data_manager_instance=None, model_dir=MODEL_DIR, model_name="active_model.joblib", scaler_name="active_scaler.joblib", test_data_name="active_test_set.joblib", threshold=0.7):
        """
        Inicializa el detector cargando el modelo, el scaler y el conjunto de prueba
        desde los archivos especificados en model_dir.
        También recibe una referencia a DataManager.

        Args:
            data_manager_instance (DataManager, optional): Una instancia de DataManager. Por defecto es None.
            model_dir (str): Directorio donde se guardarán/cargarán los archivos. Por defecto 'models'.
            model_name (str): Nombre del archivo del modelo GLM ACTIVO.
            scaler_name (str): Nombre del archivo del scaler ACTIVO (StandardScaler).
            test_data_name (str): Nombre del archivo del conjunto de prueba de evaluación ACTIVO.
            threshold (float): Umbral de probabilidad para clasificar como ataque (entre 0 y 1).
        """
        print("INFO: ThreatDetector inicializado.")
        self.data_manager_ref = data_manager_instance # Referencia guardada, no usada directamente aquí
        self.model_dir = model_dir
        # Nombres de archivos ACTIVOS
        self.active_model_name = model_name
        self.active_scaler_name = scaler_name
        self.active_test_data_name = test_data_name
        # Rutas completas a archivos ACTIVOS
        self.active_model_path = os.path.join(self.model_dir, self.active_model_name)
        self.active_scaler_path = os.path.join(self.model_dir, self.active_scaler_name)
        self.active_test_data_path = os.path.join(self.model_dir, self.active_test_data_name)

        # Inicializar componentes y lista de nombres de características
        self.model = None
        self.scaler = None
        self.test_set = None # Tupla (X_test_final, y_test_eval_cleaned, feature_names_)
        self.prediction_threshold = threshold
        self.feature_names_ = None # Para almacenar los nombres de las características de entrenamiento

        try:
            os.makedirs(self.model_dir, exist_ok=True)
            print(f"DEBUG: Directorio de modelos '{self.model_dir}' verificado/creado.")
        except Exception as e:
            print(f"ERROR: No se pudo asegurar la existencia del directorio de modelos '{self.model_dir}': {e}")
            # Continúa pero es probable que falle al guardar/cargar

        # Intentar cargar los componentes del modelo ACTIVO al iniciar
        self._load_model_components()
        print(f"INFO: ThreatDetector inicializado. Umbral: {self.prediction_threshold}")

        # Mostrar el estado de carga del modelo al final de la inicialización
        if self.model and self.scaler and self.test_set is not None and self.feature_names_ is not None:
             print("INFO: Componentes del modelo activo y nombres de características cargados exitosamente al iniciar.")
        else:
             print("WARNING: No se pudieron cargar todos los componentes del modelo activo (modelo, scaler, conjunto de prueba, nombres de características). El reentrenamiento es necesario.")


    def _load_model_components(self):
        """
        Intenta cargar el modelo GLM activo, el scaler activo, el conjunto de prueba activo
        y los nombres de las características desde los archivos guardados ACTIVOS.
        """
        print(f"DEBUG: Intentando cargar componentes ACTIVOS del modelo desde '{self.model_dir}'...")
        self.model = None
        self.scaler = None
        self.test_set = None
        self.feature_names_ = None # Resetear feature_names_

        try:
            # Cargar Modelo Activo
            if os.path.exists(self.active_model_path):
                try:
                    self.model = joblib.load(self.active_model_path)
                    print("SUCCESS: Modelo activo cargado.")
                    # Obtener feature_names si están en el modelo
                    if hasattr(self.model, 'exog_names') and self.model.exog_names is not None:
                        model_exog_names_list = [name for name in self.model.exog_names if name != 'const']
                        if model_exog_names_list: self.feature_names_ = model_exog_names_list
                except Exception as e:
                    print(f"ERROR al cargar modelo activo desde {self.active_model_path}: {e}\n{traceback.format_exc()}")
                    self.model = None
            else: print(f"INFO: Archivo de modelo activo '{self.active_model_path}' no encontrado.")

            # Cargar Scaler Activo
            if os.path.exists(self.active_scaler_path):
                try:
                    self.scaler = joblib.load(self.active_scaler_path)
                    print("SUCCESS: Scaler activo cargado.")
                    # Obtener feature_names si están en el scaler (más fiable)
                    if hasattr(self.scaler, 'feature_names_in_') and self.scaler.feature_names_in_ is not None:
                        if isinstance(self.scaler.feature_names_in_, np.ndarray):
                            self.feature_names_ = self.scaler.feature_names_in_.tolist()
                            print(f"INFO: Nombres de características actualizados desde scaler activo ({len(self.feature_names_)}).")
                        else: print("WARN: scaler.feature_names_in_ no es un array numpy.")
                except Exception as e:
                    print(f"ERROR al cargar scaler activo desde {self.active_scaler_path}: {e}\n{traceback.format_exc()}")
                    self.scaler = None
            else: print(f"INFO: Archivo de scaler activo '{self.active_scaler_path}' no encontrado.")

            # Cargar Test Set Activo y feature_names (la fuente más fiable si existe)
            if os.path.exists(self.active_test_data_path):
                try:
                    loaded_test_set_tuple = joblib.load(self.active_test_data_path)
                    print("SUCCESS: Conjunto de prueba activo cargado.")
                    if isinstance(loaded_test_set_tuple, tuple) and len(loaded_test_set_tuple) == 3:
                        self.test_set = (loaded_test_set_tuple[0], loaded_test_set_tuple[1]) # X y Y
                        if isinstance(loaded_test_set_tuple[2], list):
                             self.feature_names_ = loaded_test_set_tuple[2] # Nombres de características (lista)
                             print(f"INFO: Nombres de características actualizados desde test set activo ({len(self.feature_names_)}).")
                        else: print(f"WARN: El tercer elemento de test_set.pkl no es una lista de nombres de características.")
                    elif isinstance(loaded_test_set_tuple, tuple) and len(loaded_test_set_tuple) == 2: # Compatibilidad
                         self.test_set = loaded_test_set_tuple
                         print("WARN: test_set.pkl cargado no contiene nombres de características (formato antiguo).")
                    else: print(f"WARN: Contenido de test_set.pkl inesperado: {type(loaded_test_set_tuple)}")
                except Exception as e:
                    print(f"ERROR al cargar test set activo desde {self.active_test_data_path}: {e}\n{traceback.format_exc()}")
                    self.test_set = None
                    # No reseteamos feature_names_ aquí si ya se obtuvieron de model/scaler
            else: print(f"INFO: Archivo de test set activo '{self.active_test_data_path}' no encontrado.")

            # Verificación final de feature_names_
            if self.feature_names_ is None:
                print("ERROR CRÍTICO: No se pudieron determinar los nombres de las características del modelo/scaler/test_set. La detección fallará.")


        except Exception as e:
            print(f"ERROR inesperado durante la carga de componentes del modelo activo: {e}\n{traceback.format_exc()}")
            self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None


    def train_and_save_model(self, df_full_cleaned, sample_fraction_train=0.05):
        """
        Entrena el modelo GLM con muestreo y guarda los componentes entrenados ACTIVOS
        (modelo, scaler, conjunto de prueba final, nombres de características) en el directorio especificado.

        Args:
            df_full_cleaned (pd.DataFrame): DataFrame con los datos limpios (después de preprocess_data)
                                            pero ANTES de escalar y eliminar NaNs para el split.
                                            Debe contener una columna 'label' (Benign/Attack).
            sample_fraction_train (float): Fracción (entre 0 y 1) del conjunto de entrenamiento
                                           completo a usar para entrenar el modelo. Usar 1.0
                                           para usar todo el conjunto de entrenamiento.

        Returns:
            tuple: (bool, str) indicando éxito (True) o fracaso (False) y un mensaje para flash.
        """
        print("INFO: Iniciando proceso de entrenamiento...")
        # imports ya están al inicio del archivo
        if df_full_cleaned is None or df_full_cleaned.empty:
            msg = "Error: No hay datos válidos para entrenar el modelo."
            print(f"ERROR: {msg}")
            self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
            return False, msg

        try:
            # --- Preparación de Datos para Entrenamiento y Evaluación ---
            if 'label' not in df_full_cleaned.columns:
                msg = "Error: La columna 'label' no se encontró en los datos para el entrenamiento."
                print(f"ERROR: {msg}")
                self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
                return False, msg

            # Binarizar label (asumiendo que viene como 'Benign'/'Attack' de DataManager)
            y_full_binary = df_full_cleaned['label'].map({'Benign': 0, 'Attack': 1})
            if y_full_binary.isnull().any():
                 # Si DataManager ya lo normalizó, esto no debería pasar, pero es una verificación
                 nan_labels_original = df_full_cleaned['label'][y_full_binary.isnull()].unique()
                 msg = f"Error: La columna 'label' contiene valores no reconocidos ('Benign'/'Attack') o NaNs que no se pudieron mapear a 0/1. Valores encontrados: {nan_labels_original}"
                 print(f"ERROR: {msg}")
                 self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
                 return False, msg

            # Identificar columnas numéricas (excluyendo la binaria que acabamos de crear)
            numeric_cols = df_full_cleaned.select_dtypes(include=np.number).columns.tolist()
            feature_cols = [col for col in numeric_cols if col != 'label'] # 'label' no es numérica ahora
            # AÑADIDO: Guardar los nombres de las características que se usarán para entrenar y escalar
            self.feature_names_ = feature_cols # Esta es la lista DEFINITIVA de features
            print(f"DEBUG: Nombres de características identificados para entrenamiento: {len(self.feature_names_)}")

            if not feature_cols:
                msg = "Error: No se encontraron columnas numéricas predictoras para el entrenamiento."
                print(f"ERROR: {msg}")
                self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
                return False, msg

            X_full = df_full_cleaned[self.feature_names_].copy() # Usar la lista guardada

            # --- División en conjuntos de entrenamiento y evaluación (test) ---
            print("INFO: Realizando división inicial del dataset completo...")
            X_train_full, X_test_eval, y_train_full_binary, y_test_eval_binary = train_test_split(
                X_full, y_full_binary, test_size=0.2, random_state=42, stratify=y_full_binary
            )
            print("INFO: División inicial completa.")
            print(f"  X_train_full: {X_train_full.shape}, y_train_full_binary: {y_train_full_binary.shape}")
            print(f"  X_test_eval: {X_test_eval.shape}, y_test_eval_binary: {y_test_eval_binary.shape}")

            # --- Muestreo Estratificado del Conjunto de Entrenamiento ---
            if sample_fraction_train > 0 and sample_fraction_train < 1:
                 print(f"INFO: Aplicando muestreo estratificado al conjunto de entrenamiento ({sample_fraction_train*100:.2f}%)...")
                 _, X_train_model, _, y_train_model_binary = train_test_split(
                     X_train_full, y_train_full_binary, test_size=sample_fraction_train, random_state=42, stratify=y_train_full_binary
                 )
            else:
                 print("INFO: No se aplicó muestreo al conjunto de entrenamiento.")
                 X_train_model = X_train_full
                 y_train_model_binary = y_train_full_binary

            print(f"INFO: Dimensiones del conjunto de entrenamiento para el modelo (después de muestreo):")
            print(f"  X_train_model: {X_train_model.shape}, y_train_model_binary: {y_train_model_binary.shape}")

            # --- Manejo de NaNs FINALES y Escalado ---
            print("INFO: Eliminando filas con valores faltantes (NaNs) en los conjuntos después del split/muestreo...")
            initial_train_rows = len(X_train_model)
            initial_test_rows = len(X_test_eval)

            # Aplicar dropna en X e y JUNTOS para mantener alineación
            train_set_combined = pd.concat([X_train_model, y_train_model_binary.rename('label_binary')], axis=1).dropna().copy()
            X_train_model_cleaned = train_set_combined[self.feature_names_]
            y_train_model_binary_cleaned = train_set_combined['label_binary']

            test_set_combined = pd.concat([X_test_eval, y_test_eval_binary.rename('label_binary')], axis=1).dropna().copy()
            X_test_eval_cleaned = test_set_combined[self.feature_names_]
            y_test_eval_binary_cleaned = test_set_combined['label_binary']

            nan_removed_train = initial_train_rows - len(X_train_model_cleaned)
            nan_removed_test = initial_test_rows - len(X_test_eval_cleaned)
            if nan_removed_train > 0: print(f"INFO: {nan_removed_train} filas eliminadas con NaNs del conjunto de entrenamiento.")
            if nan_removed_test > 0: print(f"INFO: {nan_removed_test} filas eliminadas con NaNs del conjunto de evaluación.")

            # Verificar si quedan datos
            if X_train_model_cleaned.empty:
                msg = "Error: El conjunto de entrenamiento está vacío después de eliminar valores faltantes (NaNs)."
                print(f"ERROR: {msg}")
                self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
                return False, msg
            if X_test_eval_cleaned.empty:
                msg = "Error: El conjunto de evaluación está vacío después de eliminar valores faltantes (NaNs)."
                print(f"ERROR: {msg}")
                self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
                return False, msg

            print("SUCCESS: Manejo de NaNs después del split/muestreo completado.")

            # Inicializar y ajustar el escalador SOLO en el conjunto de entrenamiento
            print("INFO: Escalando datos...")
            self.scaler = StandardScaler()
            self.scaler.fit(X_train_model_cleaned) # Fit solo en X_train limpio
            X_train_model_scaled = self.scaler.transform(X_train_model_cleaned)
            X_test_eval_scaled = self.scaler.transform(X_test_eval_cleaned) # Transform en X_test limpio

            # Volver a DataFrame con las columnas correctas (usando self.feature_names_)
            X_train_model_scaled_df = pd.DataFrame(X_train_model_scaled, columns=self.feature_names_, index=X_train_model_cleaned.index)
            X_test_eval_scaled_df = pd.DataFrame(X_test_eval_scaled, columns=self.feature_names_, index=X_test_eval_cleaned.index)

            # Alinear y_train e y_test finales con los DataFrames escalados por índice
            y_train_model_final = y_train_model_binary_cleaned.loc[X_train_model_scaled_df.index].astype(int) # Asegurar tipo int
            y_test_eval_final = y_test_eval_binary_cleaned.loc[X_test_eval_scaled_df.index].astype(int) # Asegurar tipo int
            print("SUCCESS: Escalado de conjuntos de entrenamiento y prueba completado.")

            # Añadir constante para GLM
            print("INFO: Añadiendo constante para el modelo GLM...")
            X_train_model_final_const = sm.add_constant(X_train_model_scaled_df, has_constant='add')
            X_test_eval_final_const = sm.add_constant(X_test_eval_scaled_df, has_constant='add')
             # Las columnas deberían coincidir ahora si self.feature_names_ se usó consistentemente

            print("SUCCESS: Constante añadida.")

            # --- Entrenamiento del Modelo GLM ---
            print("INFO: Ajustando el modelo GLM...")
            with warnings.catch_warnings():
                # ... (filtros de warnings como los tenías) ...
                warnings.filterwarnings("ignore", category=sm.tools.sm_exceptions.PerfectSeparationWarning)
                warnings.filterwarnings('ignore', category=statsmodels.tools.sm_exceptions.ConvergenceWarning)
                self.model = sm.GLM(y_train_model_final, X_train_model_final_const, family=sm.families.Binomial()).fit()
            print("SUCCESS: Modelo GLM ajustado.")

            # --- Guardar Componentes Entrenados ACTIVOS ---
            # Guardamos el conjunto de prueba final Y los nombres de las características usados
            self.test_set = (X_test_eval_final_const, y_test_eval_final, self.feature_names_)
            print("INFO: Guardando componentes ACTIVOS del modelo...")
            os.makedirs(self.model_dir, exist_ok=True) # Asegurar que el directorio existe

            guardado_exitoso = True
            mensaje_guardado = ""
            try: joblib.dump(self.model, self.active_model_path); print("SUCCESS: Modelo activo guardado.")
            except Exception as e: guardado_exitoso = False; msg=f"Error guardando modelo activo: {e}"; print(f"ERROR: {msg}"); mensaje_guardado += msg + "; "
            try: joblib.dump(self.scaler, self.active_scaler_path); print("SUCCESS: Scaler activo guardado.")
            except Exception as e: guardado_exitoso = False; msg=f"Error guardando scaler activo: {e}"; print(f"ERROR: {msg}"); mensaje_guardado += msg + "; "
            try: joblib.dump(self.test_set, self.active_test_data_path); print("SUCCESS: Test set activo guardado.")
            except Exception as e: guardado_exitoso = False; msg=f"Error guardando test set activo: {e}"; print(f"ERROR: {msg}"); mensaje_guardado += msg + "; "

            if guardado_exitoso:
                msg = "Modelo reentrenado y componentes activos guardados exitosamente."
                print(f"SUCCESS: {msg}")
                return True, msg
            else:
                msg = f"Errores durante guardado de componentes activos: {mensaje_guardado.strip('; ')}. Reentrenamiento falló al guardar."
                print(f"ERROR: {msg}")
                # Resetear componentes en memoria si falla el guardado
                self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
                return False, msg

        except Exception as e:
            # Resetear componentes en memoria si falla el entrenamiento
            self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
            msg = f"Error durante el reentrenamiento (antes de guardar): {e}"
            print(f"ERROR: {msg}\n{traceback.format_exc()}")
            return False, msg

    def run_detection(self, df_new_data):
        """
        Ejecuta la detección de amenazas en nuevos datos usando el modelo cargado.

        Args:
            df_new_data (pd.DataFrame): DataFrame con los nuevos datos a analizar.
                                        Las columnas deben tener nombres limpios
                                        (ej. lowercase, sin espacios).
                                        Puede contener la columna 'label'.

        Returns:
            dict: Un diccionario con los resultados de la detección:
                  {'data': DataFrame con predicciones añadidas,
                   'metrics': Métricas de esta detección (si hay 'label' en df_new_data),
                   'detection_summary': Resumen de conteos de predicciones}
                  Retorna estructura de error si falta algo o falla críticamente.
        """
        print("INFO: Iniciando proceso de detección en nuevos datos...")
        # Verificar requisitos
        if self.model is None or self.scaler is None or self.feature_names_ is None:
            print("ERROR: Modelo, scaler o nombres de características no cargados. No se puede detectar.")
            return {'data': df_new_data, 'metrics': {'report': 'Modelo/Scaler/Features no cargados'}, 'detection_summary': {}}

        df_to_process = df_new_data.copy()
        original_labels = df_to_process.get('label', None) # Guardar etiquetas originales si existen
        # Asegurarse que solo trabajamos con las features esperadas
        if 'label' in df_to_process.columns:
             df_features = df_to_process[self.feature_names_].copy() # Seleccionar solo features conocidas
        else:
             df_features = df_to_process[self.feature_names_].copy() # Asume que todas las columnas son features si no hay label

        print(f"INFO: Alineando columnas de entrada ({len(df_features.columns)}) con las de entrenamiento ({len(self.feature_names_)})...")
        # Usar reindex para asegurar columnas y orden exacto, rellenando faltantes con 0
        X_new_aligned = df_features.reindex(columns=self.feature_names_, fill_value=0)

        # Verificar si hubo cambios (opcional, para logging)
        missing_cols = set(self.feature_names_) - set(df_features.columns)
        extra_cols = set(df_features.columns) - set(self.feature_names_)
        if missing_cols: print(f"WARN: Columnas faltantes rellenadas con 0: {list(missing_cols)}")
        if extra_cols: print(f"WARN: Columnas extra ignoradas: {list(extra_cols)}")

        # Manejar NaNs/Infs en datos alineados ANTES de escalar
        print("INFO: Manejando NaNs/Infs en datos alineados...")
        initial_rows_new = len(X_new_aligned)
        X_new_aligned_cleaned = X_new_aligned.replace([np.inf, -np.inf], np.nan).dropna()
        rows_removed_new = initial_rows_new - len(X_new_aligned_cleaned)
        if rows_removed_new > 0: print(f"INFO: {rows_removed_new} filas eliminadas por NaNs/Infs.")

        if X_new_aligned_cleaned.empty:
            print("WARNING: No quedan datos para predecir después de limpiar NaNs/Infs.")
            # Devolver un DF vacío con las columnas esperadas de salida
            out_cols = list(df_new_data.columns) + ['prediction_proba', 'prediction_label_binary', 'prediction_label']
            return {'data': pd.DataFrame(columns=out_cols),
                    'metrics': {'report': 'DataFrame vacío tras limpieza'},
                    'detection_summary': {}}

        # Mantener solo las filas originales que sobrevivieron a la limpieza
        df_results = df_new_data.loc[X_new_aligned_cleaned.index].copy()

        try:
            # Escalar usando el scaler ajustado
            print("INFO: Escalando nuevos datos...")
            X_new_scaled = self.scaler.transform(X_new_aligned_cleaned)
            X_new_scaled_df = pd.DataFrame(X_new_scaled, columns=self.feature_names_, index=X_new_aligned_cleaned.index)

            # Añadir constante
            print("INFO: Añadiendo constante...")
            X_new_final_const = sm.add_constant(X_new_scaled_df, has_constant='add')

            # Reindexar por si acaso (aunque add_constant debería mantener el orden)
            if hasattr(self.model, 'exog_names'):
                 X_new_final_const = X_new_final_const.reindex(columns=self.model.exog_names, fill_value=0)

            # Realizar Predicciones
            print("INFO: Realizando predicciones...")
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message="overflow encountered in exp", category=RuntimeWarning)
                prediction_proba = self.model.predict(X_new_final_const)

            # Asegurar índice y tipo correcto
            prediction_proba = pd.Series(prediction_proba, index=X_new_final_const.index)
            prediction_label = (prediction_proba >= self.prediction_threshold).astype(int)
            print("SUCCESS: Predicciones realizadas.")

            # Añadir Predicciones al DataFrame de Resultados
            df_results['prediction_proba'] = prediction_proba
            df_results['prediction_label_binary'] = prediction_label
            label_map = {0: 'Benign', 1: 'Attack'}
            df_results['prediction_label'] = prediction_label.map(label_map).fillna('Unknown')

            # Calcular Métricas si 'label' original estaba presente y es válida
            detection_metrics = {}
            if original_labels is not None:
                 # Usar las etiquetas originales correspondientes a las filas que sobrevivieron (df_results.index)
                 y_true_original_aligned = original_labels.loc[df_results.index]
                 # Intentar mapear la etiqueta original a binaria (0/1)
                 y_true_binary = y_true_original_aligned.map({'Benign': 0, 'Attack': 1})
                 # Comparar solo donde ambos (true y pred) son válidos
                 valid_comparison_index = y_true_binary.dropna().index.intersection(prediction_label.dropna().index)
                 y_true_final = y_true_binary.loc[valid_comparison_index].astype(int)
                 y_pred_final = prediction_label.loc[valid_comparison_index].astype(int)

                 if not y_true_final.empty and not y_pred_final.empty:
                     print(f"INFO: Calculando métricas de detección para {len(y_true_final)} filas...")
                     try:
                         acc = accuracy_score(y_true_final, y_pred_final)
                         cm = confusion_matrix(y_true_final, y_pred_final).tolist()
                         target_names = ['Benign', 'Attack'] # Asumiendo 0=Benign, 1=Attack
                         report = classification_report(y_true_final, y_pred_final, target_names=target_names, output_dict=True, zero_division=0)
                         detection_metrics = {'accuracy': acc, 'confusion_matrix': cm, 'report': report, 'classes': target_names}
                         print(f"SUCCESS: Métricas calculadas. Accuracy: {acc:.4f}")
                     except Exception as e:
                         print(f"ERROR calculando métricas: {e}")
                         detection_metrics = {'report': f'Error cálculo métricas: {e}'}
                 else:
                      print("WARN: No hay suficientes etiquetas verdaderas/predicciones válidas alineadas para calcular métricas.")
                      detection_metrics = {'report': 'Datos insuficientes/desalineados para métricas'}
            else:
                 print("INFO: No había columna 'label' original para calcular métricas.")
                 detection_metrics = {'report': 'Sin etiquetas originales'}

            # Resumen de Detección
            detection_summary = df_results['prediction_label'].value_counts().to_dict()
            print(f"INFO: Resumen predicciones: {detection_summary}")

            return {
                'data': df_results,
                'metrics': detection_metrics,
                'detection_summary': detection_summary
            }

        except Exception as e:
            print(f"ERROR crítico durante la detección: {e}\n{traceback.format_exc()}")
            # Devolver estructura de error
            out_cols = list(df_new_data.columns) + ['prediction_proba', 'prediction_label_binary', 'prediction_label']
            return {'data': pd.DataFrame(columns=out_cols),
                    'metrics': {'report': f'Error crítico detección: {e}'},
                    'detection_summary': {}}

    def evaluate_on_test_set(self):
        """
        Evalúa el modelo cargado en el conjunto de prueba guardado (self.test_set)
        y retorna las métricas de evaluación.

        Returns:
            dict: Diccionario con 'accuracy', 'confusion_matrix' y 'report',
                  o None/diccionario de error si falla.
        """
        print("DEBUG: Evaluando el modelo cargado en el conjunto de prueba...")
        if self.model is None or self.test_set is None or not isinstance(self.test_set, tuple) or len(self.test_set) < 2:
            print("WARN: Modelo o test set activo no disponible/inválido. No se puede evaluar.")
            return {'accuracy': None, 'report': 'Modelo o Test Set no cargado/inválido', 'confusion_matrix': None}

        try:
            X_test_final, y_test_eval_cleaned = self.test_set[0], self.test_set[1] # Desempaquetar

            if X_test_final.empty or y_test_eval_cleaned.empty:
                print("WARN: Conjunto de prueba cargado está vacío. No se puede evaluar.")
                return {'accuracy': None, 'report': 'Conjunto de prueba vacío', 'confusion_matrix': None}

            print("INFO: Realizando predicciones en el conjunto de prueba cargado...")
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message="overflow encountered in exp", category=RuntimeWarning)
                test_prediction_proba = self.model.predict(X_test_final) # X_test_final ya tiene la constante

            test_prediction_proba = pd.Series(test_prediction_proba, index=X_test_final.index)
            test_prediction_label = (test_prediction_proba >= self.prediction_threshold).astype(int)

            y_true = y_test_eval_cleaned.astype(int) # Ya debería ser 0/1
            y_pred = test_prediction_label

            # Alinear por si acaso (aunque no debería ser necesario si se guardó bien)
            common_index = y_true.index.intersection(y_pred.index)
            y_true_final = y_true.loc[common_index]
            y_pred_final = y_pred.loc[common_index]

            if y_true_final.empty or y_pred_final.empty:
                 print("WARN: No hay datos alineados en test set para métricas.")
                 return {'accuracy': None, 'report': 'Test set vacío/desalineado post-predicción', 'confusion_matrix': None}

            # Calcular métricas
            print("INFO: Calculando métricas de evaluación...")
            eval_accuracy = accuracy_score(y_true_final, y_pred_final)
            eval_conf_matrix = confusion_matrix(y_true_final, y_pred_final).tolist()
            target_names_map = {0: 'Benign', 1: 'Attack'}
            unique_classes = sorted(np.unique(np.concatenate([y_true_final.unique(), y_pred_final.unique()])))
            target_names_actual = [target_names_map.get(c, f'Class_{c}') for c in unique_classes]
            eval_report = classification_report(y_true_final, y_pred_final, target_names=target_names_actual, output_dict=True, zero_division=0)

            print(f"SUCCESS: Evaluación completada. Accuracy: {eval_accuracy:.4f}")
            return {
                'accuracy': eval_accuracy,
                'confusion_matrix': eval_conf_matrix,
                'report': eval_report,
                'classes': target_names_actual # Devolver las clases usadas en el reporte
            }

        except Exception as e:
            print(f"ERROR crítico durante la evaluación del modelo en el conjunto de prueba: {e}\n{traceback.format_exc()}")
            return {'accuracy': None, 'report': f'Error crítico evaluación: {e}', 'confusion_matrix': None}


    # --- NUEVOS MÉTODOS PARA SPRINT 5 (TR-18) ---

    def get_saved_model_list(self):
        """Devuelve una lista de nombres de archivos de modelos guardados (excluye el activo)."""
        try:
            active_model_basename = os.path.basename(self.active_model_path)
            models = [f for f in os.listdir(self.model_dir)
                      if f.endswith('.joblib') and f != active_model_basename and '_scaler' not in f and '_test_set' not in f]
            # ^ Excluir también archivos de scaler y test_set guardados por nombre
            return sorted(models)
        except FileNotFoundError:
            print("WARN: Directorio de modelos no encontrado al listar.")
            return []
        except Exception as e:
            print(f"ERROR [Detector]: Listando modelos guardados: {e}")
            return []

    def _get_associated_filenames(self, base_filename):
        """Devuelve los nombres de archivo esperados para modelo, scaler y test set basado en el nombre base."""
        if not base_filename.endswith('.joblib'): base_filename += '.joblib'
        scaler_filename = base_filename.replace('.joblib', '_scaler.joblib')
        test_set_filename = base_filename.replace('.joblib', '_test_set.joblib')
        return base_filename, scaler_filename, test_set_filename

    def save_active_model_as(self, save_name):
        """Guarda los componentes activos actuales (modelo, scaler, test_set) con un nuevo nombre base."""
        if not self.model or not self.scaler or not self.test_set:
            return False, "No hay componentes activos cargados para guardar."
        if not save_name:
            return False, "Se requiere un nombre para guardar."

        # Limpiar y asegurar nombre de archivo base (sin extensión)
        safe_filename_base = secure_filename(save_name).replace(' ', '_')
        if not safe_filename_base: return False, "Nombre inválido."

        # Obtener nombres de archivo asociados
        model_savename, scaler_savename, testset_savename = self._get_associated_filenames(safe_filename_base)

        # Rutas de destino
        model_savepath = os.path.join(self.model_dir, model_savename)
        scaler_savepath = os.path.join(self.model_dir, scaler_savename)
        testset_savepath = os.path.join(self.model_dir, testset_savename)

        # Prevenir sobrescribir modelo activo accidentalmente
        if model_savepath == self.active_model_path:
            return False, "No puedes guardar con el nombre reservado del modelo activo."

        try:
            print(f"INFO: Guardando modelo activo como '{model_savename}'...")
            # Copiar archivos activos a nuevos nombres
            if os.path.exists(self.active_model_path): shutil.copy2(self.active_model_path, model_savepath)
            else: raise FileNotFoundError("Archivo de modelo activo no encontrado.")

            if os.path.exists(self.active_scaler_path): shutil.copy2(self.active_scaler_path, scaler_savepath)
            else: print(f"WARN: Scaler activo ({self.active_scaler_path}) no encontrado, no se copiará para '{scaler_savename}'.")

            if os.path.exists(self.active_test_data_path): shutil.copy2(self.active_test_data_path, testset_savepath)
            else: print(f"WARN: Test set activo ({self.active_test_data_path}) no encontrado, no se copiará para '{testset_savename}'.")

            print(f"SUCCESS: Componentes activos guardados con base '{safe_filename_base}'.")
            return True, f'Modelo guardado como "{model_savename}".'
        except Exception as e:
            print(f"ERROR [Detector]: Guardando modelo como {model_savename}: {e}")
            # Intentar limpiar archivos parcialmente guardados si falla
            for p in [model_savepath, scaler_savepath, testset_savepath]:
                if os.path.exists(p): 
                    try: os.remove(p) 
                    except: pass
            return False, f"Error al guardar: {e}"

    def load_model_as_active(self, filename_to_load):
        """Carga un modelo guardado (y sus componentes asociados) para que sean los activos."""
        if not filename_to_load:
            return False, "Se requiere nombre de archivo para cargar."
        if filename_to_load == self.active_model_name:
             return False, "Este ya es el modelo activo."

        # Obtener nombres asociados
        model_loadname, scaler_loadname, testset_loadname = self._get_associated_filenames(filename_to_load)

        model_loadpath = os.path.join(self.model_dir, model_loadname)
        scaler_loadpath = os.path.join(self.model_dir, scaler_loadname)
        testset_loadpath = os.path.join(self.model_dir, testset_loadname)

        # Verificar existencia del modelo principal
        if not os.path.exists(model_loadpath):
            return False, f"El archivo de modelo '{model_loadname}' no existe."

        try:
            print(f"INFO: Cargando '{model_loadname}' como modelo activo...")
            # Copia el modelo seleccionado para que sea el activo
            shutil.copy2(model_loadpath, self.active_model_path)

            # Copia scaler si existe
            if os.path.exists(scaler_loadpath):
                 shutil.copy2(scaler_loadpath, self.active_scaler_path)
                 print(f"INFO: Scaler asociado '{scaler_loadname}' copiado como activo.")
            else:
                 # Si el scaler asociado no existe, ¿qué hacer? ¿Borrar el activo? Es peligroso.
                 # Por ahora, solo advertir y potencialmente limpiar el scaler activo viejo si existía.
                 print(f"WARN: Scaler asociado '{scaler_loadname}' no encontrado. El scaler activo actual ({self.active_scaler_path}) podría no ser compatible.")
                 if os.path.exists(self.active_scaler_path):
                      try: os.remove(self.active_scaler_path); print("INFO: Scaler activo anterior eliminado.")
                      except Exception as e_del_sc: print(f"WARN: No se pudo eliminar scaler activo anterior: {e_del_sc}")
                 self.scaler = None # Resetear scaler en memoria

            # Copia test set si existe
            if os.path.exists(testset_loadpath):
                 shutil.copy2(testset_loadpath, self.active_test_data_path)
                 print(f"INFO: Test set asociado '{testset_loadname}' copiado como activo.")
            else:
                 # Similar al scaler, advertir y limpiar.
                 print(f"WARN: Test set asociado '{testset_loadname}' no encontrado. El test set activo actual ({self.active_test_data_path}) podría no ser compatible.")
                 if os.path.exists(self.active_test_data_path):
                     try: os.remove(self.active_test_data_path); print("INFO: Test set activo anterior eliminado.")
                     except Exception as e_del_ts: print(f"WARN: No se pudo eliminar test set activo anterior: {e_del_ts}")
                 self.test_set = None # Resetear test set en memoria

            # Recargar componentes activos en memoria después de copiar
            self._load_model_components()

            # Verificar si la carga en memoria fue exitosa
            if self.model:
                msg = f"Modelo '{model_loadname}' ahora está activo."
                print(f"SUCCESS: {msg}")
                return True, msg
            else:
                 # La copia funcionó pero la carga en memoria falló (raro)
                 return False, f"Se copiaron archivos de '{model_loadname}' pero falló al cargarlos en memoria."
        except Exception as e:
            print(f"ERROR [Detector]: Cargando modelo {model_loadname} como activo: {e}")
            # Intentar restaurar el estado recargando componentes (puede fallar si los archivos activos fueron sobrescritos)
            self._load_model_components()
            return False, f"Error al cargar modelo: {e}"

    def delete_saved_model(self, filename_to_delete):
        """Elimina un archivo de modelo guardado y sus componentes asociados."""
        if not filename_to_delete:
            return False, "Se requiere nombre de archivo para eliminar."
        if filename_to_delete == self.active_model_name:
            return False, "No puedes eliminar el modelo activo directamente. Carga otro primero."

        # Obtener nombres asociados
        model_delname, scaler_delname, testset_delname = self._get_associated_filenames(filename_to_delete)

        model_delpath = os.path.join(self.model_dir, model_delname)
        scaler_delpath = os.path.join(self.model_dir, scaler_delname)
        testset_delpath = os.path.join(self.model_dir, testset_delname)

        # Verificar existencia del modelo principal
        if not os.path.exists(model_delpath):
            return False, f"El archivo de modelo '{model_delname}' no existe."

        deleted_files = []
        errors = []
        try:
            # Eliminar modelo
            try: os.remove(model_delpath); deleted_files.append(model_delname)
            except Exception as e: errors.append(f"modelo ({e})")

            # Eliminar scaler si existe
            if os.path.exists(scaler_delpath):
                 try: os.remove(scaler_delpath); deleted_files.append(scaler_delname)
                 except Exception as e: errors.append(f"scaler ({e})")

            # Eliminar test set si existe
            if os.path.exists(testset_delpath):
                 try: os.remove(testset_delpath); deleted_files.append(testset_delname)
                 except Exception as e: errors.append(f"test set ({e})")

            msg = f"Modelo '{filename_to_delete}' y asociados eliminados: {', '.join(deleted_files)}."
            if errors:
                 msg += f" Errores al eliminar: {', '.join(errors)}."
                 print(f"WARN: Errores al eliminar componentes asociados a {filename_to_delete}: {errors}")
                 return False, msg # Considerar False si hubo errores
            else:
                 print(f"SUCCESS: {msg}")
                 return True, msg
        except Exception as e:
            print(f"ERROR [Detector]: Eliminando modelo {filename_to_delete}: {e}")
            return False, f"Error al eliminar: {e}"