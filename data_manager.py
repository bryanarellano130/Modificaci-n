# data_manager.py
import pandas as pd
import numpy as np
import os
import re # Importar para limpieza de columnas
import traceback # Importar para imprimir tracebacks

class DataManager:
    """Gestiona la carga y preprocesamiento de datos para la aplicación web."""

    def __init__(self):
        """Inicializa el gestor de datos."""
        self.loaded_data = None
        self.processed_data = None # Contendrá datos preprocesados (aún con NaNs)
        self.loaded_filepath = None
        self.column_dtypes = None # Para referencia
        print("INFO: DataManager inicializado.")

    def load_csv_data(self, filepath):
        """
        Carga datos desde un archivo CSV, intentando con delimitadores comunes.
        """
        if not os.path.exists(filepath):
            return False, f"Error: El archivo no existe en la ruta '{filepath}'."
        print(f"INFO: Intentando leer archivo CSV '{os.path.basename(filepath)}'...")
        try:
            # Intentar con coma primero
            df = pd.read_csv(filepath, low_memory=False) # low_memory=False puede ayudar con tipos mixtos
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
                self.processed_data = None
                return False, msg

        # Si la lectura fue exitosa
        self.loaded_data = df
        self.loaded_filepath = filepath
        self.processed_data = None # Resetear datos procesados al cargar nuevos
        self.column_dtypes = self.loaded_data.dtypes # Guardar tipos originales
        msg = f"Archivo '{os.path.basename(filepath)}' cargado. ({len(self.loaded_data)} filas)"
        print(f"SUCCESS: {msg}")
        return True, msg

    def preprocess_data(self, df_to_process): # <--- ACEPTA ARGUMENTO
        """
        Realiza el preprocesamiento inicial de un DataFrame dado:
        limpieza nombres, manejo Inf->NaN, NORMALIZACIÓN DE LABEL,
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
            self.processed_data = None
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
            # ... (log opcional de columnas renombradas) ...

            # 2. Manejo Infinitos -> NaN
            numeric_cols = df.select_dtypes(include=np.number).columns
            num_infinite = np.isinf(df[numeric_cols]).values.sum()
            if num_infinite > 0:
                print(f"INFO: Encontrados {num_infinite} valores infinitos. Reemplazando con NaN.")
                df.loc[:, numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

            # 3. Normalización Label (como la versión robusta anterior)
            label_col = 'label'
            if label_col in df.columns:
                print(f"INFO: Normalizando columna '{label_col}'...")
                try:
                    df[label_col] = df[label_col].astype(str).str.strip().str.lower()
                    benign_label = 'benign'
                    attack_labels_known = { # Asegúrate que todas estén aquí
                        'dos slowloris', 'dos slowhttptest', 'dos hulk', 'dos goldeneye', 'heartbleed',
                        'portscan', 'ftp-patator', 'ssh-patator', 'bot', 'infiltration',
                        'web attack - brute force', 'web attack - xss', 'web attack - sql injection',
                        'web attack brute force', 'web attack xss', 'web attack sql injection',
                        'ddos', 'attack', 'ssh-bruteforce', 'ftp-bruteforce', 'sql injection',
                        'scan', 'malware' # Añadir las que salieron en el log del simulador
                    }
                    def map_label(lbl):
                        if pd.isna(lbl): return np.nan
                        elif lbl == benign_label: return 0
                        elif lbl in attack_labels_known: return 1
                        else: return 1 # Tratar desconocidos como ataque
                    df['label_binary'] = df[label_col].apply(map_label)
                    df[label_col] = df['label_binary'].map({0: 'Benign', 1: 'Attack', np.nan: 'Unknown/NaN'})
                    print(f"SUCCESS: Columna '{label_col}' normalizada.")
                    # print(f"INFO: Distribución '{label_col}':\n{df[label_col].value_counts(dropna=False)}")
                except Exception as e_label:
                    print(f"ERROR al normalizar '{label_col}': {e_label}")
                    # Decidimos devolver None si falla la normalización crítica
                    self.processed_data = None
                    return None, f"Error procesando columna '{label_col}': {e_label}"
            else: print(f"WARN: Columna '{label_col}' no encontrada para normalizar.")

            # 4. Eliminación columnas (lista ajustada)
            columnas_a_eliminar = [ # Nombres limpios
                'flow_bytes_s', 'flow_packets_s', 'fwd_psh_flags', 'bwd_psh_flags',
                'fwd_urg_flags', 'bwd_urg_flags', 'fin_flag_count', 'syn_flag_count',
                'rst_flag_count', 'urg_flag_count', 'cwe_flag_count', 'ece_flag_count',
                'fwd_avg_bytes_bulk', 'fwd_avg_packets_bulk', 'fwd_avg_bulk_rate',
                'bwd_avg_bytes_bulk', 'bwd_avg_packets_bulk', 'bwd_avg_bulk_rate',
                'active_std', 'idle_std', 'fwd_header_length_1', 'timestamp',
                'label_binary' # Eliminar la columna binaria si no la necesitas explícitamente después
            ]
            cols_to_drop_existing = [col for col in columnas_a_eliminar if col in df.columns]
            if cols_to_drop_existing:
                df = df.drop(columns=cols_to_drop_existing)
                print(f"INFO: Columnas eliminadas ({len(cols_to_drop_existing)}).")
            else: print("INFO: No se eliminaron columnas especificadas.")

            # 5. Eliminación duplicados
            rows_before_duplicates = len(df)
            df.drop_duplicates(inplace=True)
            duplicates_removed = rows_before_duplicates - len(df)
            if duplicates_removed > 0: print(f"INFO: {duplicates_removed} filas duplicadas eliminadas.")

            # Guardar resultado internamente Y devolverlo
            self.processed_data = df
            final_rows = len(self.processed_data)
            msg = f"Preprocesamiento completado. Filas restantes: {final_rows} (de {initial_rows})."
            print(f"SUCCESS: {msg}")
            print(f"DEBUG: NaNs restantes: {self.processed_data.isnull().sum().sum()}")
            return self.processed_data, msg # Devuelve el DF procesado y el mensaje

        except Exception as e:
            self.processed_data = None
            msg = f"Error inesperado preprocesamiento: {e}"
            print(f"ERROR: {msg}\n{traceback.format_exc()}")
            return None, msg


    # --- Métodos para obtener datos y vistas previas HTML ---
    def get_loaded_data(self):
        return self.loaded_data

    def get_processed_data(self):
        return self.processed_data

    def _generate_preview_html(self, df, rows=10, table_id="preview-table"):
        """Genera HTML para las primeras filas de un DataFrame."""
        if df is None or df.empty:
            return "<p>No hay datos disponibles.</p>"
        try:
            # escape=False es potencialmente inseguro si los datos vienen de fuentes no confiables.
            # Si confías en tus CSVs o los limpias bien, puede estar bien.
            # Considera usar escape=True y limpiar el HTML resultante con librerías como Bleach si es necesario.
            # Aplicar clases Bootstrap para mejor estilo
            html = df.head(rows).to_html(classes=['table', 'table-sm', 'table-striped', 'table-hover'],
                                         border=0, index=False, escape=False, float_format='%.4g') # Formato flotante más general
            # Reemplazar th genérico con th con scope para accesibilidad
            html = html.replace('<th>','<th scope="col">')
            return html
        except Exception as e:
            print(f"Error generando HTML preview ({table_id}): {e}")
            return "<p>Error al generar vista previa.</p>"

    def get_loaded_data_head_html(self, rows=10):
        """Vista previa HTML de datos cargados."""
        return self._generate_preview_html(self.loaded_data, rows, "loaded-preview")

    def get_processed_data_head_html(self, rows=10):
        """Vista previa HTML de datos procesados."""
        return self._generate_preview_html(self.processed_data, rows, "processed-preview")