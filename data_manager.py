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
        self.processed_data = None # processed_data ahora contendrá datos limpios de nombre/infinitos pero CON NaNs
        self.loaded_filepath = None
        self.column_dtypes = None # Para referencia futura si es necesario
        print("INFO: DataManager inicializado.") # Puedes cambiar esto por logging

    def load_csv_data(self, filepath):
        """
        Carga datos desde un archivo CSV ubicado en la ruta especificada.

        Args:
            filepath (str): La ruta completa al archivo CSV.

        Returns:
            tuple: (bool, str) indicando éxito (True) o fracaso (False) y un mensaje.
        """
        if not os.path.exists(filepath):
            return False, f"Error: El archivo no existe en la ruta '{filepath}'."

        try:
            # Intentar leer con diferentes delimitadores comunes si ',' no funciona
            print(f"INFO: Intentando leer archivo CSV '{os.path.basename(filepath)}'...")
            try:
                df = pd.read_csv(filepath)
                print("DEBUG: Archivo leído con delimitador por defecto (,).")
            except Exception as e:
                print(f"WARNING: Falló lectura con coma: {e}. Intentando con punto y coma...")
                try:
                    df = pd.read_csv(filepath, sep=';')
                    print("DEBUG: Archivo leído con delimitador (;).")
                except Exception as e_semicolon:
                    print(f"ERROR: Falló lectura con punto y coma: {e_semicolon}. No se pudo leer el archivo.")
                    self.loaded_data = None
                    self.loaded_filepath = None
                    self.processed_data = None
                    return False, f"Error: No se pudo leer el archivo CSV '{os.path.basename(filepath)}'. Verifica el delimitador. {e_semicolon}"


            self.loaded_data = df # Guardar datos crudos (después de la lectura exitosa)
            self.loaded_filepath = filepath
            self.processed_data = None # Resetear datos procesados al cargar nuevos datos
            self.column_dtypes = self.loaded_data.dtypes # Guardar tipos originales
            msg = f"Archivo '{os.path.basename(filepath)}' cargado exitosamente. ({len(self.loaded_data)} filas)"
            print(f"SUCCESS: {msg}")
            return True, msg

        except pd.errors.EmptyDataError:
            self.loaded_data = None
            self.loaded_filepath = None
            self.processed_data = None
            msg = f"Error: El archivo CSV '{os.path.basename(filepath)}' está vacío."
            print(f"WARNING: {msg}")
            return False, msg
        except Exception as e:
            self.loaded_data = None
            self.loaded_filepath = None
            self.processed_data = None
            msg = f"Error inesperado al leer el archivo CSV '{os.path.basename(filepath)}': {e}"
            print(f"ERROR: {msg}")
            import traceback
            print(traceback.format_exc()) # Imprime el traceback completo para depuración
            return False, msg
        
    def preprocess_data(self):
        """
        Realiza el preprocesamiento inicial de los datos previamente cargados:
        limpieza de nombres, manejo de Infinitos (a NaN), binarización de label,
        eliminación de columnas, eliminación de duplicados.
        NO elimina filas con NaN aquí. El manejo de NaNs final se hará en el entrenamiento.

        Returns:
            tuple: (bool, str) indicando éxito (True) o fracaso (False) y un mensaje.
        """
        if self.loaded_data is None:
            return False, "Error: No hay datos cargados para preprocesar. Carga un archivo primero."

        print("INFO: Iniciando preprocesamiento inicial de datos (nombres, infinitos, binarización label, columnas, duplicados)...")
        try:
            df_procesado = self.loaded_data.copy() # Siempre trabajar sobre una copia
            initial_rows = len(df_procesado)
            print(f"INFO: Preprocesando {initial_rows} filas...")

            # 1. Limpieza de nombres de columnas (más robusto)
            original_cols = df_procesado.columns.tolist()
            # Elimina espacios al inicio/fin, reemplaza secuencias no alfanuméricas (excepto _) con _, convierte a minúsculas
            # CORREGIDO: Eliminado regex=True
            df_procesado.columns = df_procesado.columns.str.strip().str.replace(r'[^\w]+', '_').str.lower()
            # Elimina _ al inicio/fin si quedaron
            df_procesado.columns = df_procesado.columns.str.strip('_')
            new_cols = df_procesado.columns.tolist()
            # Crear un diccionario de columnas renombradas, manejando casos donde la limpieza no cambia el nombre
            renamed_cols_dict = {}
            for original, new in zip(original_cols, new_cols):
                 # CORREGIDO: Eliminado regex=True aquí también para la comparación
                 cleaned_original_name = str(original).strip().replace(r'[^\w]+', '_').strip('_').lower()
                 if cleaned_original_name != new:
                      renamed_cols_dict[original] = new
            if renamed_cols_dict:
                 print(f"INFO: Columnas renombradas. Ej: {list(renamed_cols_dict.items())[:5]}...") # Mostrar algunos ejemplos


            # 2. Manejo de Infinitos (a NaN)
            numeric_cols_before_inf = df_procesado.select_dtypes(include=np.number).columns
            num_infinite_before = np.isinf(df_procesado[numeric_cols_before_inf]).sum().sum()
            if num_infinite_before > 0:
                print(f"INFO: Encontrados {num_infinite_before} valores infinitos en columnas numéricas. Reemplazando con NaN.")
                df_procesado[numeric_cols_before_inf] = df_procesado[numeric_cols_before_inf].replace([np.inf, -np.inf], np.nan)


            # 3. Binarización de la columna 'label' para entrenamiento binario
            # Esto debe hacerse DESPUÉS de limpiar nombres, pero ANTES de eliminar columnas si 'label' es una de ellas.
            # Asegúrate de que la columna 'label' existe y su nombre limpio es 'label'.
            label_column_name = 'label'
            print(f"INFO: Binarizando columna '{label_column_name}' para entrenamiento (Benign vs Attack)...")

            if label_column_name in df_procesado.columns:
                # Trabajar en una copia temporal de la serie para evitar SettingWithCopyWarning
                label_series = df_procesado[label_column_name].copy()

                # Identificar etiquetas de ataque (todas las que no son 'Benign')
                # Asegurarse de que 'Benign' esté escrito exactamente igual en tus datos (insensible a mayúsculas/minúsculas si es necesario)
                # Convertimos a string y minúsculas para comparación robusta si las etiquetas pueden variar en capitalización
                unique_labels = label_series.astype(str).str.strip().str.lower().unique()
                # Filtrar NaN de la lista de etiquetas únicas si pd.notna no los quitó
                unique_labels_cleaned = [lbl for lbl in unique_labels if lbl != 'nan']

                # Definir la etiqueta Benign esperada (en minúsculas para comparación)
                benign_tag_lower = 'benign'

                if benign_tag_lower in unique_labels_cleaned:
                    # Todas las demás etiquetas (que no sean benign_tag_lower y no sean NaN) son ataques
                    attack_labels_lower = [lbl for lbl in unique_labels_cleaned if lbl != benign_tag_lower]

                    if attack_labels_lower:
                        print(f"INFO: Identificadas etiquetas de ataque (en minúsculas): {attack_labels_lower}")
                        # Mapear etiquetas originales (insensible a mayúsculas/minúsculas y espacios) a 'Attack' o 'Benign'
                        # Crear un mapeo temporal a minúsculas para la binarización
                        label_series_lower = label_series.astype(str).str.strip().str.lower()

                        # Crear la columna binaria: 1 si es cualquier etiqueta de ataque (en minúsculas), 0 si es benign (en minúsculas), NaN si no es ninguna o era NaN original
                        # Usamos .loc para modificar el DataFrame original de forma segura
                        df_procesado.loc[label_series_lower == benign_tag_lower, label_column_name] = 0 # Benign es 0
                        # Para todas las etiquetas que NO SON Benign (y no son NaN), asignar 1 (Attack)
                        # Asegurarse de no incluir NaNs originales en las etiquetas de ataque
                        df_procesado.loc[label_series_lower.isin(attack_labels_lower), label_column_name] = 1 # Attack es 1


                        print("SUCCESS: Columna 'label' binarizada (0 para Benign, 1 para Attack).")
                        print(f"INFO: Valores únicos en 'label' después de binarización: {df_procesado[label_column_name].unique()}")


                    else:
                        # Si no hay etiquetas de ataque después de eliminar Benign (solo hay Benign o nada)
                        print("WARNING: No se encontraron etiquetas de ataque en los datos. El dataset parece contener solo tráfico Benign.")
                        # Mapear 'Benign' a 0. Otras etiquetas no-Benign (si existen por error) serán NaNs si no se manejan.
                        if benign_tag_lower in unique_labels_cleaned:
                             df_procesado.loc[label_series_lower == benign_tag_lower, label_column_name] = 0
                             print("INFO: Columna 'label' mapeada a 0 (Benign).")
                             print(f"INFO: Valores únicos en 'label' después de mapeo: {df_procesado[label_column_name].unique()}")
                        else:
                             print(f"WARNING: La columna '{label_column_name}' no contiene '{benign_tag_lower}' ni etiquetas de ataque válidas. No se realizó binarización efectiva.")


                else: # No se encontró la etiqueta 'Benign' en los datos
                    print(f"WARNING: La etiqueta '{benign_tag_lower}' (Benign) no se encontró en los datos. No se realizó binarización.")
                    print(f"INFO: Etiquetas únicas encontradas: {unique_labels_cleaned}")


            else:
                print(f"WARNING: Columna '{label_column_name}' no encontrada en el DataFrame. No se realizó binarización de label.")

            # --- Fin Binarización ---


            # 4. Eliminación de columnas (Asegúrate que los nombres coincidan DESPUÉS de limpiar nombres y binarizar)
            # Asegúrate de que 'label' no está en esta lista si quieres mantener la columna binarizada
            columnas_a_eliminar_limpias = [
                'flow_byts_s', 'flow_pkts_s',
                'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags', 'bwd_urg_flags',
                'fin_flag_cnt', 'syn_flag_cnt', 'rst_flag_cnt', 'urg_flag_cnt', # cnt vs count
                'cwe_flag_count', 'ece_flag_cnt', # count vs cnt, ajusta según nombres reales
                'fwd_byts_b_avg', 'fwd_pkts_b_avg', 'fwd_blk_rate_avg', # avg vs bulk
                'bwd_byts_b_avg', 'bwd_pkts_b_avg', 'bwd_blk_rate_avg', # avg vs bulk
                'active_std', 'idle_std',
                'timestamp', # Generalmente no se usa como feature numérica directa en GLM sin ingeniería de features temporal
                # Si la columna 'label' original NO se reemplazó por los binarios, y quieres eliminar la original:
                # 'label', # Eliminar si creaste una nueva columna binaria y no la renombraste a 'label'
            ]

            print(f"DEBUG: Columnas disponibles DESPUÉS de limpieza de nombres, Inf->NaN y Binarización de Label: {df_procesado.columns.tolist()}") # PARA DEPURAR NOMBRES

            # Encuentra qué columnas existen realmente en el df *después* de limpiar nombres y binarizar
            columnas_existentes_a_eliminar = [col for col in columnas_a_eliminar_limpias if col in df_procesado.columns]
            if columnas_existentes_a_eliminar:
                try:
                    df_procesado = df_procesado.drop(columns=columnas_existentes_a_eliminar)
                    print(f"INFO: Columnas eliminadas: {len(columnas_existentes_a_eliminar)} -> {', '.join(columnas_existentes_a_eliminar)}")
                except KeyError as e:
                    print(f"ERROR: Intento de eliminar columna(s) que no existen después de la limpieza de nombres o binarización: {e}")
                    pass # Continúa aunque falle el drop
            else:
                print("INFO: No se encontraron columnas especificadas para eliminar (o ya fueron eliminadas/renombradas/no existían).")


            # 5. Eliminación de duplicados (después de eliminar columnas, pero ANTES de eliminar filas con NaN)
            rows_before_duplicates = len(df_procesado)
            df_procesado.drop_duplicates(inplace=True)
            rows_after_duplicates = len(df_procesado)
            duplicates_removed_count = rows_before_duplicates - rows_after_duplicates
            if duplicates_removed_count > 0:
                print(f"INFO: {duplicates_removed_count} filas duplicadas eliminadas.")


            # --- IMPORTANTE: NO eliminamos filas con NaN aquí. Eso se hará en el entrenamiento. ---
            # df_procesado.dropna(inplace=True) # <--- COMENTADO/ELIMINADO


            # --- FIN PREPROCESAMIENTO ---

            if len(df_procesado) == 0:
                # Aunque no eliminamos todos los NaNs, podría ser que el archivo estaba vacío o solo tenía NaNs
                self.processed_data = None
                msg = "Error: Después del preprocesamiento inicial (nombres, infinitos, binarización label, columnas, duplicados), el DataFrame está vacío."
                print(f"ERROR: {msg}")
                return False, msg


            self.processed_data = df_procesado # Guardar el DataFrame preprocesado (¡CON NaNs!)
            final_rows = len(self.processed_data)
            msg = f"Preprocesamiento inicial completado. Filas restantes (con posibles NaNs): {final_rows} (de {initial_rows} iniciales)."
            print(f"SUCCESS: {msg}")
            print(f"DEBUG: Cantidad total de NaNs en el DataFrame procesado: {self.processed_data.isnull().sum().sum()}")
            print(f"DEBUG: Tipos de datos después del preprocesamiento: \n{self.processed_data.dtypes}") # Mostrar tipos de datos

            return True, msg

        except Exception as e:
            self.processed_data = None
            msg = f"Error inesperado durante el preprocesamiento: {e}"
            print(f"ERROR: {msg}")
            import traceback
            print(traceback.format_exc()) # Imprime el traceback completo para depuración
            return False, msg


    # Mantener los métodos get_loaded_data, get_processed_data, get_loaded_data_head_html, get_processed_data_head_html
    # como están, pero recordando que get_processed_data ahora puede retornar un DataFrame con NaNs.

    def get_loaded_data(self):
        """Devuelve el DataFrame original cargado."""
        return self.loaded_data

    def get_processed_data(self):
        """Devuelve el DataFrame preprocesado (nombres, infinitos, columnas, duplicados, CON NaNs)."""
        return self.processed_data

    def _get_dataframe_head_html(self, df, rows=5, table_id="dataframe-preview"):
        """Helper para convertir las primeras filas de un DF a HTML."""
        if df is None or df.empty:
            return "<p>No hay datos para mostrar.</p>"
        try:
            # Usar escape=True por defecto para seguridad.
            # float_format='%.4f' para formatear números flotantes
            return df.head(rows).to_html(classes=['data-table', 'table-sm'], border=0, table_id=table_id, escape=True, float_format='%.4f') # Añadir table-sm para tablas más compactas
        except Exception as e:
            print(f"Error generando HTML para DataFrame: {e}")
            return "<p>Error al mostrar la vista previa de los datos.</p>"

    def get_loaded_data_head_html(self, rows=5):
        """Devuelve las primeras filas de los datos cargados como tabla HTML."""
        return self._get_dataframe_head_html(self.loaded_data, rows, table_id="loaded-data-preview")

    def get_processed_data_head_html(self, rows=5):
        """Devuelve las primeras filas de los datos procesados (con NaNs) como tabla HTML."""
        return self._get_dataframe_head_html(self.processed_data, rows, table_id="processed-data-preview")

    def get_loaded_data(self):
        """Devuelve el DataFrame original cargado."""
        return self.loaded_data

    def get_processed_data(self):
        """Devuelve el DataFrame preprocesado (nombres, infinitos, columnas, duplicados, CON NaNs)."""
        return self.processed_data

    def _get_dataframe_head_html(self, df, rows=5, table_id="dataframe-preview"):
        """Helper para convertir las primeras filas de un DF a HTML."""
        if df is None or df.empty:
            return "<p>No hay datos para mostrar.</p>"
        try:
            # Usar escape=True por defecto para seguridad.
            # float_format='%.4f' para formatear números flotantes
            return df.head(rows).to_html(classes=['data-table', 'table-sm'], border=0, table_id=table_id, escape=True, float_format='%.4f') # Añadir table-sm para tablas más compactas
        except Exception as e:
            print(f"Error generando HTML para DataFrame: {e}")
            return "<p>Error al mostrar la vista previa de los datos.</p>"

    def get_loaded_data_head_html(self, rows=5):
        """Devuelve las primeras filas de los datos cargados como tabla HTML."""
        return self._get_dataframe_head_html(self.loaded_data, rows, table_id="loaded-data-preview")

    def get_processed_data_head_html(self, rows=5):
        """Devuelve las primeras filas de los datos procesados (con NaNs) como tabla HTML."""
        return self._get_dataframe_head_html(self.processed_data, rows, table_id="processed-data-preview")