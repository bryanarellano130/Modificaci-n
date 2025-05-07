# data_manager.py
import pandas as pd
import numpy as np
import os
import re # Importar para limpieza de columnas
import traceback # Importar para imprimir tracebacks

class DataManager:
    """Gestiona la carga y preprocesamiento de datos para la aplicación web."""

    def __init__(self, upload_folder='uploads', processed_filename='datos_preprocesados.csv'):
        """Inicializa el gestor de datos."""
        # Usar rutas relativas al script actual es más robusto
        self.base_dir = os.path.abspath(os.path.dirname(__file__))
        self.upload_folder = os.path.join(self.base_dir, upload_folder)
        self.processed_data_path = os.path.join(self.upload_folder, processed_filename)

        # Asegurar que la carpeta de subida exista
        os.makedirs(self.upload_folder, exist_ok=True)

        self.loaded_data = None # DataFrame cargado raw
        self.processed_data = self._load_processed_data() # Cargar al iniciar
        self.loaded_filepath = None
        self.column_dtypes = None # Para referencia
        print("INFO: DataManager inicializado.")
        if self.processed_data is not None:
             print(f"INFO: Datos procesados cargados al iniciar: {self.processed_data.shape}")
        else:
             print("INFO: No se encontraron datos procesados previos al iniciar.")


    def load_csv_data(self, filepath):
        """
        Carga datos desde un archivo CSV, intentando con delimitadores comunes.
        """
        if not os.path.exists(filepath):
            return False, f"Error: El archivo no existe en la ruta '{filepath}'."

        print(f"INFO: Intentando leer archivo CSV '{os.path.basename(filepath)}'...")
        df = None
        try:
            # Intentar con coma primero
            df = pd.read_csv(filepath, low_memory=False)
            print("DEBUG: Archivo leído con delimitador (,).")
        except Exception as e_comma:
            print(f"WARN: Falló lectura con coma: {e_comma}. Intentando con punto y coma...")
            try:
                # Intentar con punto y coma
                df = pd.read_csv(filepath, sep=';', low_memory=False)
                print("DEBUG: Archivo leído con delimitador (;).")
            except Exception as e_semicolon:
                msg = f"Error: No se pudo leer el archivo CSV '{os.path.basename(filepath)}'. Verifica delimitador o codificación. Detalles: {e_semicolon}"
                print(f"ERROR: {msg}")
                self.loaded_data = None
                self.loaded_filepath = None
                self.processed_data = None # Asegurar que no queden datos procesados viejos
                return False, msg

        # Si la lectura fue exitosa
        self.loaded_data = df
        self.loaded_filepath = filepath
        self.processed_data = None # Resetear datos procesados al cargar nuevos raw
        self.column_dtypes = self.loaded_data.dtypes # Guardar tipos originales
        msg = f"Archivo '{os.path.basename(filepath)}' cargado. ({len(self.loaded_data)} filas)"
        print(f"SUCCESS: {msg}")
        return True, msg

    def preprocess_data(self, df_to_process):
        """
        Realiza el preprocesamiento inicial de un DataFrame dado:
        limpieza nombres, manejo Inf->NaN, NORMALIZACIÓN DE LABEL (a 0/1 y texto),
        eliminación columnas, eliminación duplicados.
        Devuelve el DataFrame procesado (aún puede contener NaNs).

        Args:
            df_to_process (pd.DataFrame): El DataFrame a preprocesar.

        Returns:
            tuple: (pd.DataFrame | None, str) El DataFrame procesado o None si falla,
                   y un mensaje de estado.
        """
        if df_to_process is None or df_to_process.empty:
            # Guardar estado interno y devolver
            # self.processed_data = None # No resetear aquí si es llamado con datos nuevos
            return None, "Error: No hay datos válidos para preprocesar."

        print("INFO: Iniciando preprocesamiento inicial de datos...")
        try:
            df = df_to_process.copy() # Trabajar sobre copia del argumento
            initial_rows = len(df)
            print(f"INFO: Preprocesando {initial_rows} filas...")

            # 1. Limpieza nombres de columnas
            original_cols = df.columns.tolist()
            def clean_col_name(col_name):
                name = str(col_name).strip(); name = re.sub(r'[^\w]+', '_', name); return name.lower().strip('_')
            df.columns = [clean_col_name(col) for col in original_cols]

            # 2. Manejo Infinitos -> NaN
            numeric_cols_inf = df.select_dtypes(include=np.number).columns
            # Usar isfinite() para detectar NaN e Inf
            num_non_finite = (~np.isfinite(df[numeric_cols_inf])).values.sum()
            if num_non_finite > 0:
                 print(f"INFO: Encontrados {num_non_finite} valores no finitos (NaN/inf). Reemplazando Inf con NaN.")
                 # Solo reemplazar Inf, dropna se hará más adelante si es necesario
                 df.loc[:, numeric_cols_inf] = df[numeric_cols_inf].replace([np.inf, -np.inf], np.nan)


            # 3. Normalización Label (a 0/1 interno y 'Benign'/'Attack' final)
            label_col = 'label'
            label_binary_col = 'label_binary' # Nombre para la columna numérica interna
            if label_col in df.columns:
                print(f"INFO: Normalizando columna '{label_col}'...")
                try:
                    # Convertir a string, limpiar, lower case
                    y_str = df[label_col].astype(str).str.strip().str.lower()
                    benign_label_text = 'benign'
                    # Conjunto de etiquetas conocidas de ataque (más completo)
                    attack_labels_known = {
                        'dos slowloris', 'dos slowhttptest', 'dos hulk', 'dos goldeneye', 'heartbleed',
                        'portscan', 'ftp-patator', 'ssh-patator', 'bot', 'infiltration',
                        'web attack - brute force', 'web attack - xss', 'web attack - sql injection',
                        'web attack brute force', 'web attack xss', 'web attack sql injection',
                        'ddos', 'attack', 'ssh-bruteforce', 'ftp-bruteforce', 'sql injection',
                        'scan', 'malware' # Añadir otras si aparecen
                    }
                    # Función de mapeo más robusta
                    def map_label(lbl):
                        if pd.isna(lbl): return np.nan
                        elif lbl == benign_label_text: return 0
                        elif lbl in attack_labels_known: return 1
                        else:
                            # Intentar convertir a número por si viene como 0/1
                            try:
                                num_lbl = int(float(lbl))
                                if num_lbl == 0: return 0
                                elif num_lbl == 1: return 1
                                else: return 1 # Tratar otros números como ataque por defecto
                            except (ValueError, TypeError):
                                 return 1 # Tratar cualquier otra cosa como ataque

                    # Crear columna binaria numérica
                    df[label_binary_col] = y_str.apply(map_label)

                    # Verificar si hubo problemas (NaNs restantes en binaria)
                    if df[label_binary_col].isnull().any():
                         print(f"WARN: Algunos valores en '{label_col}' no pudieron mapearse a 0/1. Se marcarán como NaN.")

                    # Sobrescribir la columna 'label' original con texto consistente
                    label_map_text = {0: 'Benign', 1: 'Attack'}
                    df[label_col] = df[label_binary_col].map(label_map_text).fillna('Unknown/NaN') # Texto final

                    print(f"SUCCESS: Columna '{label_col}' normalizada a 'Benign'/'Attack'.")
                    print(f"INFO: Distribución '{label_col}':\n{df[label_col].value_counts(dropna=False)}")

                except Exception as e_label:
                    print(f"ERROR al normalizar '{label_col}': {e_label}")
                    # Decidimos devolver None si falla la normalización crítica
                    # self.processed_data = None # No resetear aquí
                    return None, f"Error procesando columna '{label_col}': {e_label}"
            else:
                print(f"WARN: Columna '{label_col}' no encontrada para normalizar.")


            # 4. Eliminación columnas (lista ajustada a nombres limpios)
            columnas_a_eliminar = [
                'flow_bytes_s', 'flow_packets_s', 'fwd_psh_flags', 'bwd_psh_flags',
                'fwd_urg_flags', 'bwd_urg_flags', 'fin_flag_count', 'syn_flag_count',
                'rst_flag_count', 'urg_flag_count', 'cwe_flag_count', 'ece_flag_count',
                'fwd_avg_bytes_bulk', 'fwd_avg_packets_bulk', 'fwd_avg_bulk_rate',
                'bwd_avg_bytes_bulk', 'bwd_avg_packets_bulk', 'bwd_avg_bulk_rate',
                'active_std', 'idle_std',
                'fwd_header_length_1', # Esta parece redundante si ya existe fwd_header_length
                'timestamp',           # Si existe, eliminarla
                label_binary_col       # Eliminar la columna binaria interna
            ]
            cols_to_drop_existing = [col for col in columnas_a_eliminar if col in df.columns]
            if cols_to_drop_existing:
                df = df.drop(columns=cols_to_drop_existing)
                print(f"INFO: Columnas eliminadas ({len(cols_to_drop_existing)}): {cols_to_drop_existing}")
            else:
                print("INFO: No se eliminaron columnas especificadas (o no existían).")

            # 5. Eliminación duplicados
            rows_before_duplicates = len(df)
            df.drop_duplicates(inplace=True)
            duplicates_removed = rows_before_duplicates - len(df)
            if duplicates_removed > 0: print(f"INFO: {duplicates_removed} filas duplicadas eliminadas.")

            # Guardar resultado internamente EN MEMORIA Y devolverlo
            # El guardado en ARCHIVO se hará explícitamente si es necesario (ej. con update_processed_data)
            self.processed_data = df.copy() # Guardar la versión procesada en memoria

            final_rows = len(self.processed_data)
            msg = f"Preprocesamiento completado. Filas restantes: {final_rows} (de {initial_rows})."
            print(f"SUCCESS: {msg}")
            # Los NaNs restantes serán manejados por el detector antes de escalar/entrenar
            # print(f"DEBUG: NaNs restantes en datos procesados: {self.processed_data.isnull().sum().sum()}")
            return self.processed_data, msg # Devuelve el DF procesado y el mensaje

        except Exception as e:
            # self.processed_data = None # No resetear aquí
            msg = f"Error inesperado preprocesamiento: {e}"
            print(f"ERROR: {msg}\n{traceback.format_exc()}")
            return None, msg


    def _load_processed_data(self):
        """Carga datos procesados desde el archivo si existe."""
        if os.path.exists(self.processed_data_path):
            try:
                print(f"INFO [DataMgr]: Cargando datos procesados desde {self.processed_data_path}")
                return pd.read_csv(self.processed_data_path, low_memory=False)
            except Exception as e:
                print(f"ERROR [DataMgr]: No se pudo cargar datos procesados {self.processed_data_path}: {e}")
                return None
        return None

    def get_processed_data(self):
        """Devuelve el DataFrame procesado desde memoria o lo carga desde archivo."""
        # Intenta devolver desde memoria primero
        if self.processed_data is not None:
             return self.processed_data.copy() # Devolver copia para evitar modificaciones externas
        # Si no está en memoria, intenta cargarlo desde archivo
        self.processed_data = self._load_processed_data()
        return self.processed_data.copy() if self.processed_data is not None else None

    # --- Métodos para obtener datos y vistas previas HTML ---
    def get_loaded_data(self):
         """Devuelve el DataFrame cargado raw desde memoria."""
         return self.loaded_data.copy() if self.loaded_data is not None else None

    def _generate_preview_html(self, df, rows=10, table_id="preview-table"):
        """Genera HTML para las primeras filas de un DataFrame."""
        if df is None or df.empty:
            return "<p>No hay datos disponibles.</p>"
        try:
            # Usar clases Bootstrap para mejor estilo
            html = df.head(rows).to_html(classes=['table', 'table-sm', 'table-striped', 'table-hover', 'small'], # Añadido 'small'
                                          border=0, index=False, escape=True, float_format='%.4g', na_rep='-') # escape=True es más seguro, na_rep para NaNs
            # Reemplazar th genérico con th con scope para accesibilidad
            html = html.replace('<th>','<th scope="col">')
            # Envolver en un div para scroll horizontal si es necesario
            return f'<div class="table-responsive">{html}</div>'
        except Exception as e:
            print(f"Error generando HTML preview ({table_id}): {e}")
            return "<p>Error al generar vista previa.</p>"

    def get_loaded_data_head_html(self, rows=10):
        """Vista previa HTML de datos cargados."""
        return self._generate_preview_html(self.loaded_data, rows, "loaded-preview")

    def get_processed_data_head_html(self, rows=10):
        """Vista previa HTML de datos procesados."""
        # Asegurarse de obtener la copia más reciente de memoria o archivo
        processed_df = self.get_processed_data()
        return self._generate_preview_html(processed_df, rows, "processed-preview")

    # --- NUEVO MÉTODO PARA SPRINT 5 (TR-17) ---
    def update_processed_data(self, combined_df):
        """
        Actualiza los datos procesados internos (en memoria y archivo)
        con el nuevo DataFrame combinado.

        Args:
             combined_df (pd.DataFrame): El DataFrame que contiene los datos
                                         procesados antiguos y nuevos combinados.
        Returns:
             tuple: (bool, str) Indicando éxito y mensaje.
        """
        if combined_df is None or not isinstance(combined_df, pd.DataFrame):
             return False, "Error: Se recibió un DataFrame inválido para actualizar."
        try:
            print(f"INFO [DataMgr]: Actualizando datos procesados internos con DF combinado: {combined_df.shape}")
            # Guardar en archivo
            combined_df.to_csv(self.processed_data_path, index=False)
            # Actualizar en memoria con una copia
            self.processed_data = combined_df.copy()
            msg = f"Datos procesados actualizados y guardados en {os.path.basename(self.processed_data_path)}."
            print(f"SUCCESS [DataMgr]: {msg}")
            return True, msg
        except Exception as e:
            msg = f"Error al actualizar/guardar datos procesados: {e}"
            print(f"ERROR [DataMgr]: {msg}\n{traceback.format_exc()}")
            # ¿Deberíamos intentar recargar el archivo viejo si falla el guardado?
            # self.processed_data = self._load_processed_data()
            return False, msg