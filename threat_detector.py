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

# Definir el directorio donde se guardarán/cargarán los componentes del modelo
MODEL_DIR = 'models'

class ThreatDetector:
    """
    Detecta amenazas usando un modelo de ML entrenado (GLM con muestreo).
    Gestiona el entrenamiento, guardado, carga y predicción del modelo.
    """
    def __init__(self, data_manager_instance=None, model_dir=MODEL_DIR, model_name="glm_model.pkl", scaler_name="scaler.pkl", test_data_name="test_set.pkl", threshold=0.7):
        """
        Inicializa el detector cargando el modelo, el scaler y el conjunto de prueba
        desde los archivos especificados en model_dir. También recibe una referencia a DataManager.

        Args:
            data_manager_instance (DataManager, optional): Una instancia de DataManager. Por defecto es None.
            model_dir (str): Directorio donde se guardarán/cargarán los archivos. Por defecto 'models'.
            model_name (str): Nombre del archivo del modelo GLM.
            scaler_name (str): Nombre del archivo del scaler (StandardScaler).
            test_data_name (str): Nombre del archivo del conjunto de prueba de evaluación.
            threshold (float): Umbral de probabilidad para clasificar como ataque (entre 0 y 1).
        """
        print("INFO: ThreatDetector inicializado.")
        self.data_manager_ref = data_manager_instance

        self.model_dir = model_dir
        self.model_name = model_name
        self.scaler_name = scaler_name
        self.test_data_name = test_data_name

        self.model_path = os.path.join(self.model_dir, self.model_name)
        self.scaler_path = os.path.join(self.model_dir, self.scaler_name)
        self.test_data_path = os.path.join(self.model_dir, self.test_data_name)

        # Inicializar componentes y lista de nombres de características
        self.model = None
        self.scaler = None
        self.test_set = None
        self.prediction_threshold = threshold
        self.feature_names_ = None # AÑADIDO: Para almacenar los nombres de las características de entrenamiento

        try:
            os.makedirs(self.model_dir, exist_ok=True)
            print(f"DEBUG: Directorio de modelos '{self.model_dir}' verificado/creado.")
        except Exception as e:
            print(f"ERROR: No se pudo asegurar la existencia del directorio de modelos '{self.model_dir}': {e}")
            # Continúa pero es probable que falle al guardar/cargar

        # Intentar cargar los componentes del modelo al iniciar
        self._load_model_components()

        print(f"INFO: ThreatDetector inicializado. Umbral: {self.prediction_threshold}")
        # Mostrar el estado de carga del modelo al final de la inicialización, incluyendo feature_names_
        if self.model and self.scaler and self.test_set is not None and self.feature_names_ is not None:
             print("INFO: Componentes del modelo y nombres de características cargados exitosamente al iniciar.")
        else:
             print("WARNING: No se pudieron cargar todos los componentes del modelo (modelo, scaler, conjunto de prueba, nombres de características). El reentrenamiento es necesario antes de una detección 'real' o evaluación.")


    def _load_model_components(self):
        """
        Intenta cargar el modelo GLM, el scaler, el conjunto de prueba de evaluación
        y los nombres de las características desde los archivos guardados.
        """
        print(f"DEBUG: Intentando cargar componentes del modelo desde '{self.model_dir}'...")
        self.model = None
        self.scaler = None
        self.test_set = None
        self.feature_names_ = None # AÑADIDO: Resetear feature_names_

        try:
            # Verificar si *todos* los archivos existen antes de intentar cargar
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path) and os.path.exists(self.test_data_path):
                print("INFO: Archivos de modelo, scaler y test_data encontrados. Procediendo a cargar.")
                # Cargar el modelo GLM
                try:
                     self.model = joblib.load(self.model_path)
                     print("SUCCESS: Modelo cargado.")
                     # Intentar obtener nombres de exógenas del modelo como una fuente
                     if hasattr(self.model, 'exog_names') and self.model.exog_names is not None:
                          # Eliminar 'const' si existe
                          # Convertir a lista explícitamente
                          model_exog_names_list = [name for name in self.model.exog_names if name != 'const']
                          # Solo usar si parece una lista válida de nombres de características (ej. no vacía)
                          if model_exog_names_list:
                               self.feature_names_ = model_exog_names_list
                               #print(f"DEBUG: feature_names_ obtenidos de modelo cargado. ({len(self.feature_names_)} features)")
                          #else:
                          #     print("WARNING: La lista de exog_names del modelo cargado parece vacía o inválida.")
                     #else:
                     #     print("WARNING: No se pudieron obtener exog_names del modelo cargado.")


                except Exception as e:
                     print(f"ERROR al cargar modelo desde {self.model_path}: {e}\n{traceback.format_exc()}")
                     self.model = None

                # Cargar el escalador
                try:
                     self.scaler = joblib.load(self.scaler_path)
                     print("SUCCESS: Scaler cargado.")
                     # Intentar obtener nombres de características del scaler (más fiable en versiones recientes de sklearn)
                     if hasattr(self.scaler, 'feature_names_in_') and self.scaler.feature_names_in_ is not None:
                          # Asegurarse de que se cargaron correctamente (ndarray)
                          if isinstance(self.scaler.feature_names_in_, np.ndarray):
                               self.feature_names_ = self.scaler.feature_names_in_.tolist() # Convertir a lista
                               #print(f"DEBUG: feature_names_ obtenidos de scaler cargado. ({len(self.feature_names_)} features)")
                          #else:
                          #     print("WARNING: scaler.feature_names_in_ no es un array numpy.")
                     #else:
                     #     print("WARNING: No se pudieron obtener feature_names_in_ del scaler cargado.")

                except Exception as e:
                     print(f"ERROR al cargar scaler desde {self.scaler_path}: {e}\n{traceback.format_exc()}")
                     self.scaler = None

                # Cargar el conjunto de prueba de evaluación (ahora contendrá feature_names_)
                try:
                     # Cargamos la tupla (X_test_eval_final, y_test_eval_cleaned, feature_names_)
                     loaded_test_set_tuple = joblib.load(self.test_data_path)
                     print("SUCCESS: Conjunto de prueba y nombres de características cargados.")
                     # AÑADIDO: Desempaquetar la tupla cargada. Ahora esperamos 3 elementos.
                     if isinstance(loaded_test_set_tuple, tuple) and len(loaded_test_set_tuple) == 3:
                          self.test_set = (loaded_test_set_tuple[0], loaded_test_set_tuple[1]) # X y Y
                          # La fuente más fiable de feature_names_ es la guardada explícitamente en el test_set pickle
                          if isinstance(loaded_test_set_tuple[2], list):
                               self.feature_names_ = loaded_test_set_tuple[2] # Nombres de características (lista)
                               print(f"INFO: Nombres de características cargados desde test_set.pkl. ({len(self.feature_names_)} features)")
                          else:
                               print(f"WARNING: El tercer elemento de test_set.pkl no es una lista de nombres de características. Tipo: {type(loaded_test_set_tuple[2])}")
                               # Si el tercer elemento no es la lista esperada, intentamos los fallbacks de model/scaler
                               if self.model and hasattr(self.model, 'exog_names'):
                                    self.feature_names_ = [name for name in self.model.exog_names if name != 'const']
                                    print(f"INFO: Usando exog_names del modelo como fallback para feature_names_ ({len(self.feature_names_) if self.feature_names_ else 0}).")
                               elif self.scaler and hasattr(self.scaler, 'feature_names_in_'):
                                     if isinstance(self.scaler.feature_names_in_, np.ndarray):
                                          self.feature_names_ = self.scaler.feature_names_in_.tolist()
                                          print(f"INFO: Usando feature_names_in_ del scaler como fallback para feature_names_ ({len(self.feature_names_) if self.feature_names_ else 0}).")
                               else:
                                   self.feature_names_ = None # Asegurar que sea None si todos los fallbacks fallan


                     elif isinstance(loaded_test_set_tuple, tuple) and len(loaded_test_set_tuple) == 2:
                          # Compatible hacia atrás si solo se guardaron X e Y (versiones anteriores)
                          self.test_set = loaded_test_set_tuple
                          print("WARNING: test_set.pkl cargado no contiene nombres de características (formato antiguo).")
                          # Intentar obtener de model o scaler como fallback (menos fiable)
                          if self.model and hasattr(self.model, 'exog_names'):
                               self.feature_names_ = [name for name in self.model.exog_names if name != 'const']
                               print(f"INFO: Usando exog_names del modelo como fallback para feature_names_ ({len(self.feature_names_) if self.feature_names_ else 0}).")
                          elif self.scaler and hasattr(self.scaler, 'feature_names_in_'):
                                if isinstance(self.scaler.feature_names_in_, np.ndarray):
                                     self.feature_names_ = self.scaler.feature_names_in_.tolist()
                                     print(f"INFO: Usando feature_names_in_ del scaler como fallback para feature_names_ ({len(self.feature_names_) if self.feature_names_ else 0}).")
                          else:
                              self.feature_names_ = None # Asegurar que sea None si todos los fallbacks fallan


                     else:
                          print(f"WARNING: El contenido del archivo test_set.pkl no es una tupla (X, y, feature_names) o (X, y) como se esperaba. Tipo: {type(loaded_test_set_tuple)}")
                          self.test_set = None # Considerar el test set inválido
                          self.feature_names_ = None # Considerar feature_names_ inválido

                except Exception as e:
                     print(f"ERROR al cargar conjunto de prueba desde {self.test_data_path}: {e}\n{traceback.format_exc()}")
                     self.test_set = None
                     self.feature_names_ = None

            else:
                print(f"INFO: Archivos de modelo/scaler/test_data no encontrados en '{self.model_dir}'.")
                self.model = None
                self.scaler = None
                self.test_set = None
                self.feature_names_ = None


        except Exception as e:
            print(f"ERROR inesperado durante la carga de componentes del modelo: {e}\n{traceback.format_exc()}")
            self.model = None
            self.scaler = None
            self.test_set = None
            self.feature_names_ = None


    def train_and_save_model(self, df_full_cleaned, sample_fraction_train=0.05):
        """
        Entrena el modelo GLM con muestreo y guarda los componentes entrenados
        (modelo, scaler, conjunto de prueba final, nombres de características) en el directorio especificado.

        Args:
            df_full_cleaned (pd.DataFrame): DataFrame con los datos limpios (después de preprocess_data)
                                            pero ANTES de escalar y eliminar NaNs para el split.
                                            Debe contener una columna 'label'.
            sample_fraction_train (float): Fracción (entre 0 y 1) del conjunto de entrenamiento
                                           completo a usar para entrenar el modelo. Usar 1.0
                                           para usar todo el conjunto de entrenamiento.

        Returns:
            tuple: (bool, str) indicando éxito (True) o fracaso (False) y un mensaje para flash.
        """
        print("INFO: Iniciando proceso de entrenamiento...")

        import statsmodels.api as sm
        import statsmodels.tools.sm_exceptions

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

            numeric_cols = df_full_cleaned.select_dtypes(include=np.number).columns.tolist()
            feature_cols = [col for col in numeric_cols if col != 'label']
            target_col = 'label'

            if not feature_cols:
                 msg = "Error: No se encontraron columnas numéricas predictoras para el entrenamiento (después de excluir 'label')."
                 print(f"ERROR: {msg}")
                 self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
                 return False, msg

            # AÑADIDO: Guardar los nombres de las características que se usarán para entrenar y escalar
            self.feature_names_ = feature_cols
            print(f"DEBUG: Nombres de características identificados para entrenamiento: {len(self.feature_names_)}")

            X_full = df_full_cleaned[feature_cols].copy() # Usar .copy() para evitar SettingWithCopyWarning
            y_full = df_full_cleaned[target_col].copy()   # Usar .copy()

            # Verificar y potencialmente convertir la variable objetivo a binaria (0/1)
            # Esta lógica es robusta y verifica si la columna 'label' es numérica (0/1) o si puede ser mapeada a 0/1
            # Asegúrate de que DataManager ya ha hecho la binarización a 0 y 1 para el mejor resultado.
            if y_full.dtype not in [np.int64, np.float64] or not y_full.dropna().isin([0, 1]).all():
                 print(f"INFO: Columna 'label' es tipo {y_full.dtype} o contiene valores distintos de 0/1. Intentando asegurar formato numérico binario (0/1)...")
                 try:
                      # Intenta mapear valores comunes a 0/1. Maneja NaNs.
                      y_full_numeric = y_full.astype(str).str.strip().str.lower().map({'benign': 0, 'attack': 1, '0': 0, '1': 1, 0: 0, 1: 1}).dropna()

                      if not y_full_numeric.empty and y_full_numeric.isin([0, 1]).all():
                           unique_numeric_labels = y_full_numeric.unique()
                           if len(unique_numeric_labels) != 2: # Asegura que hay 0s y 1s
                                msg = f"Error: Después de mapear a 0/1, la columna 'label' tiene {len(unique_numeric_labels)} valores únicos ({unique_numeric_labels}). Se requieren exactamente 2 (0 y 1)."
                                print(f"FATAL ERROR: {msg}")
                                self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
                                return False, msg
                           else:
                                y_full = y_full_numeric # Usar la versión binarizada y limpia
                                print("SUCCESS: Columna 'label' asegurada como binaria numérica (0/1).")
                      else:
                           msg = f"Error: La columna 'label' no pudo convertirse a formato numérico binario (0/1) válido. Asegúrate de que contiene solo 'Benign' y etiquetas de ataque (o 0s/1s)."
                           print(f"FATAL ERROR: {msg}")
                           self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
                           return False, msg

                 except Exception as e:
                      msg = f"Error inesperado al intentar binarizar/validar la columna 'label': {e}\n{traceback.format_exc()}"
                      print(f"FATAL ERROR: {msg}")
                      self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
                      return False, msg

            else:
                 print(f"INFO: Columna 'label' ya es numérica binaria (0/1) y válida.")


            # --- División en conjuntos de entrenamiento y evaluación (test) ---
            print("INFO: Realizando división inicial del dataset completo...")
            # Asegurar que y_full.dropna() no esté vacío y tenga al menos dos clases para estratificar
            if y_full.dropna().empty or y_full.dropna().nunique() < 2:
                 msg = "Error: La columna 'label' está vacía, solo contiene NaNs o tiene menos de dos clases válidas para la división estratificada."
                 print(f"FATAL ERROR: {msg}")
                 self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
                 return False, msg

            # statsmodels requiere que la variable de estratificación no tenga NaN
            valid_indices = y_full.dropna().index
            X_full_stratify = X_full.loc[valid_indices]
            y_full_stratify = y_full.loc[valid_indices]

            X_train_full, X_test_eval, y_train_full, y_test_eval = train_test_split(
                X_full_stratify, y_full_stratify, test_size=0.2, random_state=42, stratify=y_full_stratify
            )
            print("INFO: División inicial completa.")
            print(f"  X_train_full: {X_train_full.shape}, y_train_full: {y_train_full.shape}")
            print(f"  X_test_eval: {X_test_eval.shape}, y_test_eval: {y_test_eval.shape}")


            # --- Muestreo Estratificado del Conjunto de Entrenamiento ---
            if sample_fraction_train > 0 and sample_fraction_train < 1:
                print(f"INFO: Aplicando muestreo estratificado al conjunto de entrenamiento ({sample_fraction_train*100:.2f}%)...")

                if y_train_full.empty or y_train_full.nunique() < 2:
                     msg = "Error: El conjunto de entrenamiento completo está vacío o tiene menos de dos clases válidas para el muestreo estratificado."
                     print(f"FATAL ERROR: {msg}")
                     self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
                     return False, msg

                # statsmodels requiere que la variable de estratificación no tenga NaN
                valid_train_indices = y_train_full.dropna().index
                X_train_full_stratify = X_train_full.loc[valid_train_indices]
                y_train_full_stratify = y_train_full.loc[valid_train_indices]

                if y_train_full_stratify.empty:
                     msg = "Error: El conjunto de entrenamiento completo está vacío después de eliminar NaNs en la etiqueta. No se puede realizar el muestreo estratificado."
                     print(f"FATAL ERROR: {msg}")
                     self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
                     return False, msg

                _, X_train_model, _, y_train_model = train_test_split(
                    X_train_full_stratify, y_train_full_stratify, test_size=sample_fraction_train, random_state=42, stratify=y_train_full_stratify # Estratificar con la versión sin NaNs
                )
            else:
                # Si sample_fraction_train es 1 o <= 0, usar el conjunto completo de entrenamiento
                print("INFO: No se aplicó muestreo al conjunto de entrenamiento.")
                # Eliminar NaNs en y_train_full si sample_fraction es 1
                valid_train_indices = y_train_full.dropna().index
                X_train_model = X_train_full.loc[valid_train_indices]
                y_train_model = y_train_full.loc[valid_train_indices]
                if y_train_model.empty:
                     msg = "Error: El conjunto de entrenamiento está vacío después de eliminar NaNs en la etiqueta (sin muestreo)."
                     print(f"FATAL ERROR: {msg}")
                     self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
                     return False, msg


            print(f"INFO: Dimensiones del conjunto de entrenamiento para el modelo (después de muestreo y limpieza etiqueta):")
            print(f"  X_train_model: {X_train_model.shape}, y_train_model: {y_train_model.shape}")


            # --- Manejo de NaNs FINALES y Escalado ---
            print("INFO: Eliminando filas con valores faltantes (NaNs) en los conjuntos después del split/muestreo...")
            initial_train_rows = len(X_train_model)
            initial_test_rows = len(X_test_eval)

            # Asegurarse de eliminar NaNs de X e y juntos para mantener la alineación
            # Aplicar dropna en X_train_model e y_train_model juntos
            train_set_combined = pd.concat([X_train_model, y_train_model.rename('label')], axis=1).dropna().copy()
            X_train_model_cleaned = train_set_combined[self.feature_names_] # Usar self.feature_names_ para seleccionar
            y_train_model_cleaned = train_set_combined['label']

            # Aplicar dropna en X_test_eval e y_test_eval juntos
            test_set_combined = pd.concat([X_test_eval, y_test_eval.rename('label')], axis=1).dropna().copy()
            X_test_eval_cleaned = test_set_combined[self.feature_names_] # Usar self.feature_names_ para seleccionar
            y_test_eval_cleaned = test_set_combined['label']


            nan_removed_train = initial_train_rows - len(X_train_model_cleaned)
            nan_removed_test = initial_test_rows - len(X_test_eval_cleaned)

            if nan_removed_train > 0 or nan_removed_test > 0:
                 print(f"INFO: {nan_removed_train} filas eliminadas con NaNs del conjunto de entrenamiento.")
                 print(f"INFO: {nan_removed_test} filas eliminadas con NaNs del conjunto de evaluación.")
            else:
                 print("INFO: No se encontraron filas con NaNs para eliminar después del split/muestreo.")


            # Verificar si quedan datos después de eliminar NaNs
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

            # Inicializar y ajustar el escalador SOLO en el conjunto de entrenamiento muestreado
            print("INFO: Escalando datos...")
            from sklearn.preprocessing import StandardScaler

            self.scaler = StandardScaler() # Usar StandardScaler
            # Asegurarse de que los datos sean numéricos y finitos. dropna() ya se hizo.
            # Fit en el conjunto de entrenamiento LIMPIO (sin NaNs)
            self.scaler.fit(X_train_model_cleaned) # Fit solo en X_train_model_cleaned
            X_train_model_scaled = self.scaler.transform(X_train_model_cleaned)
            # Transformar el conjunto de evaluación usando el mismo escalador
            X_test_eval_scaled = self.scaler.transform(X_test_eval_cleaned)

            # Volver a DataFrame para mantener nombres de columnas y usar con statsmodels
            # Las columnas son self.feature_names_
            X_train_model_scaled_df = pd.DataFrame(X_train_model_scaled, columns=self.feature_names_, index=X_train_model_cleaned.index) # Mantener índice y usar self.feature_names_
            X_test_eval_scaled_df = pd.DataFrame(X_test_eval_scaled, columns=self.feature_names_, index=X_test_eval_cleaned.index) # Mantener índice y usar self.feature_names_

            # Alinear y_train_model_cleaned e y_test_eval_cleaned con los DataFrames escalados por índice
            y_train_model_final = y_train_model_cleaned.loc[X_train_model_scaled_df.index]
            y_test_eval_final = y_test_eval_cleaned.loc[X_test_eval_scaled_df.index]


            print("SUCCESS: Escalado de conjuntos de entrenamiento y prueba completado.")

            # Añadir una constante para el intercepto del modelo GLM
            print("INFO: Añadiendo constante para el modelo GLM...")
            import statsmodels.api as sm

            X_train_model_final = sm.add_constant(X_train_model_scaled_df, has_constant='add')
            X_test_eval_final_const = sm.add_constant(X_test_eval_scaled_df, has_constant='add') # Renombrado para claridad

            # Asegurarse de que las columnas de test coincidan con las de train (orden y existencia)
            train_cols = X_train_model_final.columns
            test_cols_before_reindex = X_test_eval_final_const.columns
            # Esto DEBERÍA coincidir si feature_names_ se usó correctamente, pero se mantiene la verificación
            if not train_cols.equals(test_cols_before_reindex):
                print("WARNING: Columnas del conjunto de evaluación desalineadas con el de entrenamiento final (después de add_constant). Realineando...")
                X_test_eval_final_const = X_test_eval_final_const.reindex(columns=train_cols, fill_value=0)

            print("SUCCESS: Constante añadida y columnas alineadas.")


            # --- Entrenamiento del Modelo GLM ---
            print("INFO: Ajustando el modelo GLM (esto puede tardar y generar advertencias de separación perfecta)...")
            with warnings.catch_warnings():
                 warnings.filterwarnings("ignore", message="Maximum Likelihood optimization failed to converge.")
                 warnings.filterwarnings("ignore", message="The discrete likelihood functions may be poorly approximated by the continuous likelihood functions.")
                 warnings.filterwarnings("ignore", message="The reliance on convergence of the iterative process may be problematic.")
                 warnings.filterwarnings("ignore", category=sm.tools.sm_exceptions.PerfectSeparationWarning)
                 warnings.filterwarnings('ignore', category=statsmodels.tools.sm_exceptions.ConvergenceWarning)


                 self.model = sm.GLM(y_train_model_final, X_train_model_final, family=sm.families.Binomial()).fit()

            print("SUCCESS: Modelo GLM ajustado.")

            # --- Guardar Componentes Entrenados ---
            # Guardamos X_test_eval_final_const, y_test_eval_final Y self.feature_names_
            self.test_set = (X_test_eval_final_const, y_test_eval_final, self.feature_names_) # AÑADIDO: Guardar feature_names_ en el test_set tuple

            print(f"INFO: Verificando estado y tipo de objetos antes de guardar:")
            print(f"  self.model is None: {self.model is None}")
            print(f"  self.scaler is None: {self.scaler is None}")
            print(f"  self.test_set is None: {self.test_set is None}")
            print(f"  self.feature_names_ is None: {self.feature_names_ is None}")

            if isinstance(self.test_set, tuple) and len(self.test_set) == 3: # Esperamos 3 elementos ahora
                print(f"  self.test_set[0] type: {type(self.test_set[0])}, shape: {self.test_set[0].shape if hasattr(self.test_set[0], 'shape') else 'N/A'}")
                print(f"  self.test_set[1] type: {type(self.test_set[1])}, shape: {self.test_set[1].shape if hasattr(self.test_set[1], 'shape') else 'N/A'}")
                print(f"  self.test_set[2] type: {type(self.test_set[2])}, len: {len(self.test_set[2]) if hasattr(self.test_set[2], '__len__') else 'N/A'}")
            else:
                 print(f"  self.test_set type or structure unexpected: {type(self.test_set)}")


            print(f"INFO: Guardando componentes del modelo en '{self.model_dir}'...")
            try:
                 os.makedirs(self.model_dir, exist_ok=True)
                 print(f"DEBUG: Directorio '{self.model_dir}' verificado/creado antes de guardar.")
            except Exception as e:
                 print(f"ERROR: No se pudo asegurar la existencia del directorio '{self.model_dir}' antes de guardar: {e}")
                 self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
                 return False, f"Error crítico: No se puede acceder o crear el directorio para guardar el modelo: {e}"

            guardado_exitoso = True
            mensaje_guardado = ""

            try:
                print(f"INFO: Intentando guardar modelo GLM en {self.model_path}")
                joblib.dump(self.model, self.model_path)
                print(f"SUCCESS: Modelo GLM guardado en {self.model_path}")
            except Exception as e:
                guardado_exitoso = False
                mensaje_guardado += f"Error al guardar modelo: {e}; "
                print(f"ERROR al guardar modelo en {self.model_path}: {e}\n{traceback.format_exc()}")

            try:
                print(f"INFO: Intentando guardar scaler en {self.scaler_path}")
                joblib.dump(self.scaler, self.scaler_path)
                print(f"SUCCESS: Scaler guardado en {self.scaler_path}")
            except Exception as e:
                guardado_exitoso = False
                mensaje_guardado += f"Error al guardar scaler: {e}; "
                print(f"ERROR al guardar scaler en {self.scaler_path}: {e}\n{traceback.format_exc()}")

            try:
                print(f"INFO: Intentando guardar conjunto de prueba y nombres de características en {self.test_data_path}")
                # Guardamos self.test_set que ahora es una tupla de 3 elementos
                joblib.dump(self.test_set, self.test_data_path)
                print(f"SUCCESS: Conjunto de prueba y nombres de características guardados en {self.test_data_path}")
            except Exception as e:
                guardado_exitoso = False
                mensaje_guardado += f"Error al guardar conjunto de prueba y nombres de características: {e}; "
                print(f"ERROR al guardar conjunto de prueba y nombres de características en {self.test_data_path}: {e}\n{traceback.format_exc()}")

            if guardado_exitoso:
                msg = "Modelo reentrenado y componentes guardados exitosamente."
                print(f"SUCCESS: {msg}")
                return True, msg
            else:
                msg = f"Error(es) durante el guardado de componentes: {mensaje_guardado.strip('; ')}. El reentrenamiento falló en la fase de guardado."
                print(f"ERROR: {msg}")
                self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
                return False, msg

        except Exception as e:
            self.model = None; self.scaler = None; self.test_set = None; self.feature_names_ = None
            msg = f"Error durante el reentrenamiento (antes de guardar): {e}"
            print(f"ERROR: {msg}\n{traceback.format_exc()}")
            return False, msg


    def run_detection(self, df_new_data):
        """
        Ejecuta la detección de amenazas en nuevos datos usando el modelo cargado.

        Args:
            df_new_data (pd.DataFrame): DataFrame con los nuevos datos a analizar.
                                        Puede contener la columna 'label'. Las columnas
                                        deben tener nombres limpios (ej. lowercase, sin espacios).

        Returns:
            dict: Un diccionario con los resultados de la detección:
                  {'data': DataFrame con predicciones añadidas,
                   'metrics': Métricas de esta detección (si hay 'label' en df_new_data),
                   'detection_summary': Resumen de conteos de predicciones}
                  Retorna una estructura con info de error si no hay modelo/scaler/feature_names_ cargado o si hay un error crítico.
        """
        print("INFO: Iniciando proceso de detección en nuevos datos...")

        if self.model is None or self.scaler is None or self.feature_names_ is None:
            print("ERROR: Modelo, scaler o nombres de características no cargados. No se puede ejecutar la detección. Por favor, reentrena el modelo.")
            return {'data': df_new_data, 'metrics': {'accuracy': None, 'report': 'Modelo no cargado o feature names faltantes', 'confusion_matrix': None}, 'detection_summary': {}}


        # Asegurarse de trabajar con una copia y guardar las etiquetas originales si existen
        df_to_process = df_new_data.copy()
        original_labels = df_to_process.get('label', None)
        if 'label' in df_to_process.columns:
             # Eliminar la columna 'label' antes de la selección y alineación de características
             df_to_process = df_to_process.drop(columns=['label'])

        # Asegurarse de que solo se usan columnas numéricas
        X_new_numeric = df_to_process.select_dtypes(include=np.number).copy()


        # CORRECCIÓN CLAVE AQUÍ: Alinear las columnas de los nuevos datos EXCTAMENTE con self.feature_names_
        # Los datos de entrada (df_new_data) DEBEN tener sus nombres de columnas limpios ANTES de llamar a este método
        # (ej. minúsculas, sin espacios ni caracteres especiales, como hace DataManager.preprocess_data)
        print(f"INFO: Alineando columnas de nuevos datos a las {len(self.feature_names_)} características de entrenamiento...")

        # Usar reindex para seleccionar, ordenar y añadir columnas faltantes con 0
        X_new_aligned = X_new_numeric.reindex(columns=self.feature_names_, fill_value=0)

        # Verificar si hay columnas que faltan en los datos de entrada pero estaban en entrenamiento
        # Estas ya fueron añadidas con 0 por reindex, pero es útil para logging
        missing_cols_in_new_data = set(self.feature_names_) - set(X_new_numeric.columns)
        if missing_cols_in_new_data:
             print(f"WARNING: Columnas de entrenamiento faltantes en los datos de entrada (después de limpieza de nombres externa): {list(missing_cols_in_new_data)}. Rellenadas con 0.")

        # Verificar si hay columnas extra en los datos de entrada que no estaban en entrenamiento
        # Estas fueron ignoradas por reindex
        extra_cols_in_new_data = set(X_new_numeric.columns) - set(self.feature_names_)
        if extra_cols_in_new_data:
             print(f"WARNING: Columnas extra en los datos de entrada (después de limpieza de nombres externa) que no estaban en entrenamiento: {list(extra_cols_in_new_data)}. Serán ignoradas.")

        # DEBUGging: Verificar columnas después de reindex
        # print(f"DEBUG: Columnas de X_new_aligned after reindex: {X_new_aligned.columns.tolist()}")
        # print(f"DEBUG: Expected feature names (self.feature_names_): {self.feature_names_}")
        # if set(X_new_aligned.columns) != set(self.feature_names_) or list(X_new_aligned.columns) != self.feature_names_:
        #      print("FATAL DEBUG: Column names MISMATCH after reindex - This should not happen if reindex works!")


        # Manejar NaNs o Infinitos residuales en los datos alineados ANTES de escalar
        print("INFO: Manejando NaNs/Infs en datos alineados antes de predecir...")
        initial_rows_new = len(X_new_aligned)
        # Reemplazar infinitos por NaN y luego eliminar filas con NaNs
        X_new_aligned_cleaned = X_new_aligned.replace([np.inf, -np.inf], np.nan).dropna()
        rows_removed_new = initial_rows_new - len(X_new_aligned_cleaned)

        if rows_removed_new > 0:
             print(f"INFO: {rows_removed_new} filas eliminadas de los nuevos datos debido a NaNs/Infs antes de la predicción.")

        if X_new_aligned_cleaned.empty:
             print("WARNING: No quedan datos para predecir después de eliminar NaNs/Infs.")
             # Retornar estructura con info sobre el vaciado
             return {'data': pd.DataFrame(columns=list(df_new_data.columns) + ['prediction_proba', 'prediction_label_binary', 'prediction_label']),
                     'metrics': {'accuracy': None, 'report': 'DataFrame vacío después de limpieza', 'confusion_matrix': None},
                     'detection_summary': {'Status': 'No data after cleaning'}}

        # Necesitamos alinear los datos originales para la salida con las filas que quedaron después del dropna
        # Esto asegura que las etiquetas originales (si existen) y otras columnas no numéricas
        # correspondientes a las filas que se van a predecir, se mantengan.
        # Usar .loc[X_new_aligned_cleaned.index] asegura que solo tomamos las filas que sobrevivieron
        df_results = df_new_data.loc[X_new_aligned_cleaned.index].copy()


        try:
            print("INFO: Escalando nuevos datos alineados y limpios...")
            # Escalar los nuevos datos alineados y limpios usando el scaler ajustado
            # El escalador ahora espera las columnas exactas en X_new_aligned_cleaned
            X_new_scaled = self.scaler.transform(X_new_aligned_cleaned)

            # Volver a DataFrame para mantener nombres de columnas (que son self.feature_names_) y usar con statsmodels
            X_new_scaled_df = pd.DataFrame(X_new_scaled, columns=self.feature_names_, index=X_new_aligned_cleaned.index)


            print("INFO: Añadiendo constante a nuevos datos escalados...")
            import statsmodels.api as sm

            X_new_final = sm.add_constant(X_new_scaled_df, has_constant='add')

            # Asegurarse de que las columnas estén en el mismo orden que las del modelo entrenado (incluida la constante)
            # Esto DEBERÍA coincidir si feature_names_ se usó correctamente y add_constant funciona como se espera
            if self.model is not None and hasattr(self.model, 'exog_names'):
                model_exog_names = self.model.exog_names
                 # Verificar si las columnas coinciden. Si no, reindexar por seguridad (raro que pase aquí si todo va bien)
                if not X_new_final.columns.equals(model_exog_names):
                     print("WARNING: Columnas de datos nuevos (con constante) desalineadas con las del modelo entrenado. Realineando.")
                     X_new_final = X_new_final.reindex(columns=model_exog_names, fill_value=0)
                #else:
                #    print("SUCCESS: Columnas de datos nuevos (con constante) alineadas con las del modelo.") # Mensaje muy frecuente

            else:
                print("WARNING: No se pudieron obtener nombres de exógenas del modelo para verificar alineación final.")


            # --- Realizar Predicciones ---
            print("INFO: Realizando predicciones...")
            try:
                with warnings.catch_warnings():
                    # Ignorar warnings de overflow durante la predicción si ocurren
                    warnings.filterwarnings("ignore", message="overflow encountered in exp", category=RuntimeWarning)
                    prediction_proba = self.model.predict(X_new_final)

                print("SUCCESS: Predicción de probabilidades completada.")

                if pd.api.types.is_numeric_dtype(prediction_proba):
                    # Asegurarse de que prediction_proba tiene el índice correcto para alinear con df_results
                    prediction_proba = pd.Series(prediction_proba, index=X_new_final.index)
                    prediction_label = (prediction_proba >= self.prediction_threshold).astype(int)
                    print(f"SUCCESS: Clasificación binaria usando umbral {self.prediction_threshold} completada.")
                else:
                    print(f"ERROR: prediction_proba no es numérico ({prediction_proba.dtype}). No se pudo aplicar el umbral.")
                    prediction_proba = pd.Series(np.nan, index=df_results.index)
                    prediction_label = pd.Series(np.nan, index=df_results.index)


            except Exception as e:
                 print(f"ERROR durante la predicción o aplicación del umbral: {e}\n{traceback.format_exc()}")
                 prediction_proba = pd.Series(np.nan, index=df_results.index)
                 prediction_label = pd.Series(np.nan, index=df_results.index)


            # --- Añadir Predicciones al DataFrame de Resultados ---
            # df_results ya está alineado con las filas que sobrevivieron la limpieza antes de escalar
            # Asegurarse de que las series de predicción también estén alineadas por índice
            df_results['prediction_proba'] = prediction_proba
            df_results['prediction_label_binary'] = prediction_label

            # Convertir la etiqueta binaria (0/1) de vuelta a las etiquetas de texto ('Benign', 'Attack')
            label_inverse_map_supposed = {0: 'Benign', 1: 'Attack'}
            df_results['prediction_label'] = df_results['prediction_label_binary'].map(label_inverse_map_supposed).fillna('Unknown')

            print("SUCCESS: Predicciones añadidas al DataFrame.")

            # --- Calcular Métricas de esta Detección (SI los datos de entrada tenían 'label') ---
            # Esto es opcional y solo útil si estás prediciendo en datos que YA tienen etiquetas verdaderas (ej. un test set)
            # Si estás prediciendo en datos NUEVOS sin etiquetas, esta sección se saltará.
            detection_metrics = {}
            # Verificar si la columna 'label' original existía y si hay predicciones binarias válidas
            # y si original_labels no es None o vacío
            if original_labels is not None and not original_labels.empty and 'prediction_label_binary' in df_results.columns and not df_results['prediction_label_binary'].dropna().empty:

                 # Obtener y_true del DataFrame de resultados (df_results) que está alineado
                 # con las filas que sobrevivieron a la limpieza y tienen predicciones.
                 if 'label' in df_results.columns:
                      print("INFO: Columna 'label' original disponible en los resultados. Calculando métricas de detección...")

                      y_true_raw = df_results['label'].copy() # Usar la columna 'label' de df_results (ya alineada)

                      # Intentar mapear a 0/1 de forma flexible (int/float 0/1, string '0'/'1', string 'benign'/'attack')
                      y_true_processed = y_true_raw.astype(str).str.strip().str.lower()
                      y_true_mapped = y_true_processed.map({'benign': 0, 'attack': 1, '0': 0, '1': 1, 0: 0, 1: 1})

                      # Limpiar NaNs/mapeos fallidos y asegurar tipo int
                      y_true = y_true_mapped.dropna().astype(int)

                      # Alinear y_pred con y_true (esto elimina predicciones si la etiqueta original correspondiente era NaN o inválida)
                      y_pred = df_results['prediction_label_binary'].loc[y_true.index].dropna() # Asegurar que y_pred también está limpio de NaNs y alineado

                      # Asegurarse de que ambos tienen el mismo índice final
                      common_index = y_true.index.intersection(y_pred.index)
                      y_true_final = y_true.loc[common_index]
                      y_pred_final = y_pred.loc[common_index]

                      if not y_true_final.empty and not y_pred_final.empty and len(y_true_final) == len(y_pred_final):
                           print(f"INFO: {len(y_true_final)} filas válidas para cálculo de métricas de detección.")
                           # Verificar que y_true solo contenga 0s y 1s antes de calcular métricas
                           if not y_true_final.isin([0, 1]).all():
                                print("WARNING: Las etiquetas verdaderas obtenidas para métricas no son binarias (0/1). No se calcularán métricas.")
                                detection_metrics = {'accuracy': None, 'report': 'Etiquetas verdaderas no binarias para métricas', 'confusion_matrix': None}
                           else:
                                try:
                                     detection_accuracy = accuracy_score(y_true_final, y_pred_final)

                                     target_names_map_for_report = {0: 'Benign', 1: 'Attack'}
                                     unique_classes_present = np.unique(np.concatenate([y_true_final.unique(), y_pred_final.unique()]))
                                     sorted_classes = sorted(unique_classes_present)
                                     target_names_actual = [target_names_map_for_report.get(c, f'Class_{c}') for c in sorted_classes]

                                     detection_conf_matrix = confusion_matrix(y_true_final, y_pred_final).tolist()
                                     evaluation_report = classification_report(y_true_final, y_pred_final, target_names=target_names_actual, output_dict=True, zero_division=0)

                                     detection_metrics = {
                                          'accuracy': detection_accuracy,
                                          'confusion_matrix': detection_conf_matrix,
                                          'report': evaluation_report
                                     }
                                     print(f"SUCCESS: Métricas de detección calculadas. Accuracy: {detection_accuracy:.4f}")
                                except Exception as e:
                                     print(f"ERROR al calcular métricas para esta detección: {e}\n{traceback.format_exc()}")
                                     detection_metrics = {'accuracy': None, 'report': f'Error cálculo métricas: {e}', 'confusion_matrix': None}
                      else:
                           print("WARNING: Después de binarizar, limpiar NaNs y alinear, las etiquetas originales y predicciones no se alinean o están vacías. No se pudieron calcular métricas de detección.")
                           detection_metrics = {'accuracy': None, 'report': 'Etiquetas originales no válidas o desalineadas para métricas', 'confusion_matrix': None}
                 else:
                      print("INFO: La columna 'label' original no estaba presente en el DataFrame de resultados después de la limpieza. No se calcularán métricas de detección.")
                      detection_metrics = {'accuracy': None, 'report': 'Columna label no disponible en resultados', 'confusion_matrix': None}

            else:
                 print("INFO: Datos de entrada no contenían columna 'label', predicciones inválidas o no suficientes datos para calcular métricas.")
                 detection_metrics = {'accuracy': None, 'report': 'Sin etiquetas originales válidas o predicciones inválidas', 'confusion_matrix': None}

            # --- Resumen de Detección ---
            detection_summary = {}
            if 'prediction_label_binary' in df_results.columns:
                 valid_predictions = df_results['prediction_label_binary'].dropna()
                 if not valid_predictions.empty:
                     attack_count = valid_predictions.sum()
                     benign_count = len(valid_predictions) - attack_count
                     unknown_count = df_results['prediction_label_binary'].isnull().sum()
                     detection_summary = {'Attack': int(attack_count), 'Benign': int(benign_count), 'Unknown': int(unknown_count)}
                     print(f"INFO: Resumen de predicciones: {detection_summary}")
                 else:
                     detection_summary = {'Status': 'No valid predictions'}
                     print("INFO: No hay predicciones válidas para resumir.")
            else:
                 print("WARNING: prediction_label_binary no está en los resultados. No se generará resumen de conteos.")
                 detection_summary = {'Status': 'No binary predictions column'}


            # Retornar resultados incluyendo el DataFrame con predicciones
            return {
                'data': df_results,
                'metrics': detection_metrics, # Pasar las métricas calculadas (o el diccionario de error)
                'detection_summary': detection_summary
            }

        except Exception as e:
            print(f"ERROR crítico durante la ejecución de la detección: {e}\n{traceback.format_exc()}")
            # Retornar estructura de error si algo falla durante el cálculo
            return {'data': pd.DataFrame(columns=list(df_new_data.columns) + ['prediction_proba', 'prediction_label_binary', 'prediction_label']),
                    'metrics': {'accuracy': None, 'report': f'Error crítico detección: {e}', 'confusion_matrix': None},
                    'detection_summary': {'Status': 'Error during detection'}}


    def evaluate_on_test_set(self):
        """
        Evalúa el modelo cargado en el conjunto de prueba guardado (self.test_set)
        y retorna las métricas de evaluación (Accuracy, Matriz de Confusión, Reporte).

        Returns:
            dict: Diccionario con 'accuracy', 'confusion_matrix' y 'report',
                  o None si el modelo o el conjunto de prueba no están cargados,
                  o si ocurre un error durante la evaluación.
        """
        print("DEBUG: Evaluando el modelo cargado en el conjunto de prueba...")

        # Verificar si el modelo, scaler, test_set y feature_names_ están cargados y en el formato esperado
        # self.test_set ahora debe ser una tupla de 3 elementos: (X_test_final, y_test_eval_final, feature_names_)
        if self.model is None or self.scaler is None or self.test_set is None or not isinstance(self.test_set, tuple) or len(self.test_set) < 3 or self.feature_names_ is None:
            print("WARNING: Modelo, scaler, conjunto de prueba o nombres de características no disponible/inválido/no cargado. No se puede evaluar.")
            return {'accuracy': None, 'report': 'Modelo no cargado o test set inválido', 'confusion_matrix': None}

        try:
            # Desempaquetar el conjunto de prueba guardado. Esperamos X_test_final, y_test_eval_cleaned
            X_test_final = self.test_set[0]
            y_test_eval_cleaned = self.test_set[1]
            # No necesitamos self.test_set[2] (feature_names_) aquí directamente porque X_test_final ya tiene las columnas correctas

            if X_test_final.empty or y_test_eval_cleaned.empty:
                 print("WARNING: El conjunto de prueba cargado está vacío. No se puede evaluar.")
                 return {'accuracy': None, 'report': 'Conjunto de prueba vacío', 'confusion_matrix': None}


            print("INFO: Realizando predicciones en el conjunto de prueba cargado...")
            try:
                with warnings.catch_warnings():
                     # Ignorar warnings de overflow durante la predicción si ocurren
                     warnings.filterwarnings("ignore", message="overflow encountered in exp", category=RuntimeWarning)
                     test_prediction_proba = self.model.predict(X_test_final)

                print("SUCCESS: Predicción de probabilidades en conjunto de prueba completada.")

                if pd.api.types.is_numeric_dtype(test_prediction_proba):
                     # Asegurarse de que test_prediction_proba tiene el índice correcto
                     test_prediction_proba = pd.Series(test_prediction_proba, index=X_test_final.index)
                     test_prediction_label = (test_prediction_proba >= self.prediction_threshold).astype(int)
                     print(f"SUCCESS: Clasificación binaria en conjunto de prueba usando umbral {self.prediction_threshold} completada.")
                else:
                     print(f"ERROR: test_prediction_proba no es numérico ({test_prediction_proba.dtype}). No se pudo aplicar el umbral para evaluación.")
                     return {'accuracy': None, 'report': 'Error aplicando umbral en test set', 'confusion_matrix': None}

            except Exception as e:
                 print(f"ERROR durante la predicción en conjunto de prueba o aplicación del umbral: {e}\n{traceback.format_exc()}")
                 return {'accuracy': None, 'report': f'Error predicción/umbral en test set: {e}', 'confusion_matrix': None}


            y_true = y_test_eval_cleaned.astype(int) # Asegurar tipo entero
            y_pred = test_prediction_label # Las predicciones ya son int (0 o 1)

            # Asegurar que ambos tienen el mismo índice final después de cualquier limpieza implícita en predicción/umbral
            common_index = y_true.index.intersection(y_pred.index)
            y_true_final = y_true.loc[common_index]
            y_pred_final = y_pred.loc[common_index]


            if not y_true_final.isin([0, 1]).all():
                 print("ERROR: Las etiquetas verdaderas del conjunto de prueba no son binarias (0/1). No se pueden calcular métricas.")
                 return {'accuracy': None, 'report': 'Etiquetas verdaderas del test set no binarias', 'confusion_matrix': None}


            if y_true_final.empty or y_pred_final.empty or len(y_true_final) != len(y_pred_final):
                 print("WARNING: Después de alinear, las etiquetas verdaderas o predicciones del conjunto de prueba están vacías o desalineadas. No se pueden calcular métricas.")
                 return {'accuracy': None, 'report': 'Etiquetas o predicciones del test set desalineadas/vacías', 'confusion_matrix': None}


            # Calcular métricas
            print("INFO: Calculando métricas de evaluación...")
            try:
                 eval_accuracy = accuracy_score(y_true_final, y_pred_final)
                 eval_conf_matrix = confusion_matrix(y_true_final, y_pred_final).tolist()

                 target_names_map_for_report = {0: 'Benign', 1: 'Attack'} # Usar este mapeo para el reporte
                 unique_classes_present = np.unique(np.concatenate([y_true_final.unique(), y_pred_final.unique()]))
                 sorted_classes = sorted(unique_classes_present)
                 target_names_actual = [target_names_map_for_report.get(c, f'Class_{c}') for c in sorted_classes]

                 eval_report = classification_report(y_true_final, y_pred_final, target_names=target_names_actual, output_dict=True, zero_division=0) # zero_division=0 evita errores si no hay predicciones para una clase
                 print("SUCCESS: Reporte de clasificación calculado.")
            except Exception as e:
                 print(f"ERROR al generar reporte de clasificación: {e}\n{traceback.format_exc()}")
                 eval_report = {'report': f'Error generando reporte: {e}'}


            print(f"SUCCESS: Evaluación en conjunto de prueba completada. Accuracy: {eval_accuracy:.4f}")

            return {
                'accuracy': eval_accuracy,
                'confusion_matrix': eval_conf_matrix,
                'report': eval_report # Devolver el diccionario del reporte
            }

        except Exception as e:
            print(f"ERROR crítico durante la evaluación del modelo en el conjunto de prueba: {e}\n{traceback.format_exc()}")
            return {'accuracy': None, 'report': f'Error crítico evaluación: {e}', 'confusion_matrix': None}