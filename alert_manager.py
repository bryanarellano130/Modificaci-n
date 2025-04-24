# alert_manager.py
import datetime
import json
import os
import pandas as pd
import traceback

ALERTS_FILE = "alerts_data.json" # Archivo para guardar/cargar las alertas
DETECTION_HISTORY_FILE = "detection_history.json" # Archivo para guardar/cargar el historial de detecciones

class AlertManager:
    """
    Gestiona la generación, visualización, estado y persistencia de las alertas
    y el historial de detecciones.
    """

    def __init__(self, config_defaults=None):
        """
        Inicializa el gestor de alertas y historial, cargando datos existentes si los hay.

        Args:
            config_defaults (dict, optional): Valores por defecto para la configuración.
                                                Defaults to {'severity_threshold': 'Media', 'notify_email': False}.
        """
        self.alerts = [] # Para las alertas específicas
        self.detection_history = [] # Lista para el historial de detecciones
        # Asegurar que self.config siempre sea un dict si no se provee config_defaults válido
        self.config = config_defaults if isinstance(config_defaults, dict) else {
            'severity_threshold': 'Media',
            'notify_email': False
        }
        self._next_id = 1 # Para asignar IDs únicos a las alertas
        self._load_alerts() # Cargar alertas al iniciar
        self._load_detection_history() # Cargar historial de detecciones al iniciar

        print("INFO: AlertManager inicializado.")
        print(f"INFO: Configuración inicial de alertas: {self.config}")
        # Evitar imprimir miles de alertas si el archivo es grande
        print(f"INFO: {len(self.alerts)} alertas cargadas. Próximo ID: {self._next_id}")
        print(f"INFO: {len(self.detection_history)} entradas de historial de detección cargadas.")


    def _load_alerts(self):
        """Carga las alertas desde el archivo JSON si existe."""
        if os.path.exists(ALERTS_FILE):
            try:
                with open(ALERTS_FILE, 'r', encoding='utf-8') as f:
                    # Manejar caso de archivo vacío
                    content = f.read()
                    if not content:
                        print(f"INFO: El archivo de alertas '{ALERTS_FILE}' está vacío.")
                        self.alerts = []
                    else:
                        self.alerts = json.loads(content) # Usar loads para leer el string
                # Asegurarse que el ID siguiente sea mayor que cualquier ID existente
                if self.alerts:
                    # Filtrar posibles None o entradas sin 'id' antes de calcular max
                    valid_ids = [alert.get('id', 0) for alert in self.alerts if isinstance(alert.get('id'), int)]
                    max_id = max(valid_ids) if valid_ids else 0
                    self._next_id = max_id + 1
                else:
                    self._next_id = 1
            except json.JSONDecodeError:
                print(f"ERROR: El archivo de alertas '{ALERTS_FILE}' está corrupto. Empezando con lista vacía.")
                self.alerts = []
                self._next_id = 1
            except Exception as e:
                print(f"ERROR: No se pudo cargar el archivo de alertas '{ALERTS_FILE}': {e}")
                print(traceback.format_exc())
                self.alerts = []
                self._next_id = 1
        else:
            print(f"INFO: No se encontró archivo de alertas '{ALERTS_FILE}'. Empezando con lista vacía.")
            self.alerts = []
            self._next_id = 1


    def _load_detection_history(self):
        """Carga el historial de detecciones desde el archivo JSON si existe."""
        if os.path.exists(DETECTION_HISTORY_FILE):
            try:
                with open(DETECTION_HISTORY_FILE, 'r', encoding='utf-8') as f:
                     # Manejar caso de archivo vacío
                    content = f.read()
                    if not content:
                        print(f"INFO: El archivo de historial '{DETECTION_HISTORY_FILE}' está vacío.")
                        self.detection_history = []
                    else:
                        self.detection_history = json.loads(content) # Usar loads para leer el string
                # Convertir timestamps de vuelta a objetos datetime si es necesario para ordenación,
                # aunque para display en templates el string ISO es suficiente.
                # Jinja filter | format_datetime en base.html maneja el string ISO.
            except json.JSONDecodeError:
                print(f"ERROR: El archivo de historial '{DETECTION_HISTORY_FILE}' está corrupto. Empezando con lista vacía.")
                self.detection_history = []
            except Exception as e:
                print(f"ERROR: No se pudo cargar el archivo de historial '{DETECTION_HISTORY_FILE}': {e}")
                print(traceback.format_exc())
                self.detection_history = []
        else:
            print(f"INFO: No se encontró archivo de historial '{DETECTION_HISTORY_FILE}'. Empezando con lista vacía.")
            self.detection_history = []

    def _save_detection_history(self):
        """Guarda la lista actual del historial de detecciones en el archivo JSON."""
        # print("DEBUG: -> Dentro _save_detection_history") # Descomentar para depurar
        try:
            # Asegurar que los objetos datetime se conviertan a string ISO si no lo están ya
            # (aunque en la función detect ya los guardamos como ISO, doble chequeo)
            def serialize_datetime(obj):
                if isinstance(obj, datetime.datetime):
                    return obj.isoformat()
                # Permitir la serialización de DataFrames a dicts si es necesario (aunque se supone que no se guardan)
                if isinstance(obj, pd.DataFrame):
                     return obj.to_dict()
                # Permitir la serialización de Series a dicts si es necesario (aunque se supone que no se guardan)
                if isinstance(obj, pd.Series):
                     return obj.to_dict()
                # Manejar tipos numéricos de numpy si es necesario
                if isinstance(obj, (int, float, bool)):
                     return obj
                # Manejar numpy arrays si es necesario
                if isinstance(obj, np.ndarray):
                     return obj.tolist()

                raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

            with open(DETECTION_HISTORY_FILE, 'w', encoding='utf-8') as f:
                # Usamos default=serialize_datetime por si acaso hay algún objeto no serializable
                json.dump(self.detection_history, f, indent=4, ensure_ascii=False, default=serialize_datetime)
            # print(f"DEBUG: Historial de detecciones guardado en {DETECTION_HISTORY_FILE}") # Descomentar para depurar
        except IOError as e:
            print(f"ERROR: No se pudo guardar el archivo de historial '{DETECTION_HISTORY_FILE}': {e}")
        except Exception as e:
            print(f"ERROR: Error inesperado al guardar historial: {e}")
            print(traceback.format_exc())
        # print("DEBUG: <- Saliendo de _save_detection_history") # Descomentar para depurar


    def add_detection_to_history(self, history_entry):
        """
        Añade una entrada de resumen de detección al historial, evitando duplicados exactos.
        La entrada debe ser un diccionario serializable (sin DataFrames o objetos complejos no convertidos).
        """
        # print("DEBUG: -> Dentro add_detection_to_history") # Descomentar para depurar
        if isinstance(history_entry, dict):
            # print("DEBUG: -> history_entry es un diccionario") # Descomentar para depurar

            # --- COMPROBACIÓN ANTI-DUPLICADOS ---
            # Comprueba si una entrada EXACTAMENTE IGUAL ya existe en las últimas N entradas
            # (Revisar las últimas 10, por ejemplo, para eficiencia)
            already_exists = False
            check_range = min(10, len(self.detection_history)) # Revisa las últimas 10 o menos
            # Itera desde la entrada más reciente hacia atrás
            for i in range(1, check_range + 1):
                 # Compara la entrada nueva con una entrada existente del historial
                 # Para comparación de diccionarios, asegura que ambos son serializables primero si hay tipos complejos
                 # Como ya guardamos data_head como list of dicts, la comparación directa deberia funcionar si no hay otros tipos complejos
                 if self.detection_history[-i] == history_entry: # Comparación directa de diccionarios
                     already_exists = True
                     # print(f"DEBUG: -> Entrada duplicada detectada. No se añadirá.") # Descomentar para depurar
                     break # Sale del bucle for si encuentra duplicado

            # Si no es duplicado, procede a añadir y guardar
            if not already_exists:
                # Opcional: Limitar el tamaño del historial si crece demasiado
                max_history_entries = 100 # Por ejemplo, guardar solo las últimas 100 entradas
                if len(self.detection_history) >= max_history_entries:
                    # print("DEBUG: -> Límite tamaño historial alcanzado, eliminando más antiguo.") # Descomentar para depurar
                    self.detection_history.pop(0) # Eliminar la entrada más antigua
                    # print("DEBUG: <- Eliminado entrada más antigua.") # Descomentar para depurar

                # print("DEBUG: -> Añadiendo history_entry a self.detection_history") # Descomentar para depurar
                self.detection_history.append(history_entry) # <-- Aquí se añade al historial en memoria
                # print(f"DEBUG: <- Añadido history_entry. Tamaño actual del historial: {len(self.detection_history)}") # Descomentar para depurar

                # print("DEBUG: -> Llamando a _save_detection_history()") # Descomentar para depurar
                self._save_detection_history() # Guardar la lista actualizada en el archivo JSON
                # print("DEBUG: <- _save_detection_history() retornó.") # Descomentar para depurar

                # print("INFO: Resumen de detección añadido al historial.") # Descomentar para log menos ruidoso
            # else:
                 # print("DEBUG: -> Entrada duplicada omitida.") # Descomentar para depurar


        else:
            print(f"ERROR: Intento de añadir al historial con un formato incorrecto: {type(history_entry)}")
        # print("DEBUG: <- Saliendo de add_detection_to_history") # Descomentar para depurar


    def get_detection_history(self):
        """Devuelve la lista del historial de detecciones (ordenadas, más recientes primero)."""
        # El historial ya se añade en orden cronológico, pero lo ordenamos por si acaso
        # Ordenar por timestamp descendente
        history_to_sort = self.detection_history
        try:
             # Asegurarse de que cada entrada tiene un timestamp y que es un string comparable
             return sorted(
                 history_to_sort,
                 key=lambda x: x.get('timestamp', '1970-01-01T00:00:00Z') if isinstance(x, dict) else '1970-01-01T00:00:00Z', # Usar un timestamp ISO por defecto para evitar errores si falta o no es dict
                 reverse=True
             )
        except Exception as e:
             print(f"ERROR ordenando historial de detecciones: {e}")
             print(traceback.format_exc())
             return history_to_sort # Devolver sin ordenar si falla


    # --- MÉTODO generate_alerts (CORREGIDO) ---
    def generate_alerts(self, detection_results_df):
        """
        Genera alertas basadas en los resultados de detección proporcionados.

        Args:
            detection_results_df (pd.DataFrame): DataFrame con los resultados de la detección,
                                                 debe incluir 'prediction_label' y otras
                                                 columnas relevantes (src_ip, dst_ip, label, etc.).

        Returns:
            tuple: (int, list) El número de nuevas alertas generadas y la lista
                   de los diccionarios de esas nuevas alertas.
        """
        if detection_results_df is None or detection_results_df.empty:
            print("INFO: No hay resultados de detección para generar alertas.")
            return 0, [] # Devolver tupla con lista vacía

        # Asegurarse de que la columna 'prediction_label' existe antes de filtrar
        if 'prediction_label' not in detection_results_df.columns:
             print("WARN: Columna 'prediction_label' no encontrada en los resultados para generar alertas.")
             return 0, []

        # --- FILTRADO CLAVE CORREGIDO: Buscar 'Attack' con mayúsculas y minúsculas correctas ---
        # Usar .copy() para evitar SettingWithCopyWarning
        potential_attacks = detection_results_df[detection_results_df['prediction_label'] == 'Attack'].copy() # <--- CORREGIDO: 'Attack' en lugar de 'ATTACK'

        new_alerts_list = [] # Lista para guardar solo las nuevas de esta ejecución
        print(f"INFO: Analizando {len(potential_attacks)} detecciones de posibles ataques...") # Esto DEBERÍA MOSTRAR > 0 ahora si hay ataques

        if potential_attacks.empty:
            print("INFO: No se detectaron ataques (según 'prediction_label' == 'Attack') que cumplan el umbral de severidad (si aplica).") # Mensaje más claro
            return 0, []


        # --- Lógica Opcional: Filtrar por Umbral de Severidad (Revisión) ---
        # Mapeo de etiquetas originales a severidad - Asegúrate de que todas tus posibles etiquetas de ataque estén aquí
        # Si una etiqueta de ataque del modelo no está en este mapa, por defecto será 'Media'
        # Usamos .get('label', 'Unknown_Attack') para obtener la etiqueta original o un valor por defecto si no está
        severity_map = {
            'ddos': 'Alta', # Usar minúsculas para coincidir con la limpieza de nombres
            'scan': 'Media',
            'malware': 'Crítica',
            'portscan': 'Media',
            'infiltration': 'Alta',
            'benign': 'Baja',
            'attack': 'Media', # Valor por defecto si la etiqueta original de ataque no está mapeada específicamente
            'unknown_attack': 'Media' # Por si get('label') retorna None y fallback es 'Unknown_Attack'
        }
        severity_levels = {'Baja': 1, 'Media': 2, 'Alta': 3, 'Crítica': 4}
        # Usar .get con valor por defecto para evitar KeyError si 'severity_threshold' no está en config
        # Convertir el umbral configurado a su nivel numérico. Por defecto 'Media' (nivel 2) si no se puede obtener de config o mapear
        threshold_level = severity_levels.get(self.config.get('severity_threshold', 'Media'), 2)


        # Iterar solo sobre las filas que ya son ataques ('Attack')
        for index, row in potential_attacks.iterrows():
            # Intentar obtener la etiqueta original si existe, de lo contrario usar 'Attack' como fallback para el tipo
            # Convertir a minúsculas para usar el severity_map consistentemente
            original_label = str(row.get('label', 'Attack')).lower()

            # Determinar la severidad basada en la etiqueta original (o la predicción si no hay original)
            # Usar .get con un valor por defecto si la etiqueta (en minúsculas) no está en severity_map
            severity = severity_map.get(original_label, severity_map.get('attack', 'Media')) # Fallback a 'attack' si la etiqueta original no mapea


            current_severity_level = severity_levels.get(severity, 1) # Nivel numérico de la severidad determinada


            # Verificar si la severidad de esta detección cumple o supera el umbral configurado
            if current_severity_level >= threshold_level:
                 # Si cumple el umbral, crea la alerta
                 try:
                      # Asegurarse de que 'prediction_proba' existe antes de intentar usarla
                      prediction_proba = row.get('prediction_proba', None)
                      proba_str = f"Proba: {prediction_proba:.4f}" if prediction_proba is not None else "Proba: N/A"

                      # Usar la etiqueta original o la predicción 'Attack' para el tipo de alerta si la original es BENIGN u otro no ataque
                      # Si la etiqueta original es 'Benign', pero la predicción es 'Attack', la alerta debe ser de "Amenaza Detectada"
                      # Si la etiqueta original es un tipo de ataque (DDoS, Scan, etc.) Y la predicción es 'Attack', usar ese tipo
                      # Si la etiqueta original es 'Benign' Y la predicción es 'Attack', el tipo es "Amenaza Detectada (Positivo Falso?)".
                      # Simplificamos: si la predicción es 'Attack', el tipo es "Amenaza Detectada" y el detalle puede incluir la etiqueta original.

                      # Usar la etiqueta original si es un tipo de ataque conocido, de lo contrario usar "Amenaza Detectada"
                      alert_type = f"Amenaza Detectada ({original_label.capitalize()})" if original_label in severity_map and original_label != 'benign' else "Amenaza Detectada"

                      alert = {
                          "id": self._next_id,
                          "timestamp": datetime.datetime.now().isoformat(timespec='seconds'),
                          "type": alert_type,
                          "severity": severity, # La severidad determinada (ej: Alta, Media)
                          # Incluir detalles relevantes de la fila + probabilidad
                          "details": f"SRC: {row.get('src_ip', 'N/A')}, DST: {row.get('dst_ip', 'N/A')}, Proto: {row.get('protocol', 'N/A')}, {proba_str}, Original Label: {row.get('label', 'N/A')}",
                          "reviewed": False
                      }
                      self.alerts.append(alert) # Añadir a la lista principal
                      new_alerts_list.append(alert) # Añadir a la lista de nuevas
                      self._next_id += 1

                      # Simulación de notificación por correo electrónico
                      if self.config.get('notify_email', False):
                           print(f"SIMULACION EMAIL [{severity.upper()}]: {alert['type']} - {alert['details']}")

                 except Exception as e:
                      print(f"ERROR creando/guardando alerta para fila (índice {index}): {e}")
                      print(traceback.format_exc())
                      # Continúa con la siguiente fila si falla una


        new_alerts_count = len(new_alerts_list)
        if new_alerts_count > 0:
            # print(f"INFO: {new_alerts_count} nuevas alertas generadas (cumpliendo umbral '{self.config.get('severity_threshold', 'Media')}').") # Ya se imprime en app.py
            self._save_alerts() # <-- Guardar después de generar nuevas alertas
            return new_alerts_count, new_alerts_list # Devolver conteo y lista
        else:
            # print(f"INFO: No se generaron nuevas alertas que cumplan el umbral '{self.config.get('severity_threshold', 'Media')}'.") # Ya se imprime en app.py
            return 0, [] # Devolver 0 y lista vacía


    # --- MÉTODO get_alerts (PARA MOSTRAR ALERTAS EN EL DASHBOARD/ALERTS PAGE) ---
    def get_alerts(self, show_all=False):
        """Devuelve la lista de alertas (ordenadas, más recientes primero)."""
        alerts_to_sort = self.alerts
        if not show_all:
            alerts_to_sort = [a for a in self.alerts if not a.get('reviewed', False)]
        # Ordenar por timestamp descendente (más reciente primero)
        # Manejar casos donde timestamp podría faltar o ser inválido
        try:
            return sorted(
                alerts_to_sort,
                key=lambda x: x.get('timestamp', '1970-01-01T00:00:00Z') if isinstance(x, dict) else '1970-01-01T00:00:00Z', # Usar un timestamp ISO por defecto para evitar errores
                reverse=True
            )
        except Exception as e:
            print(f"ERROR sorting alerts: {e}")
            print(traceback.format_exc())
            return alerts_to_sort # Return unsorted list on error


    # --- MÉTODO _save_alerts ---
    def _save_alerts(self):
        """Guarda la lista actual de alertas en el archivo JSON."""
        # print("DEBUG: -> Dentro _save_alerts") # Descomentar para depurar
        try:
            with open(ALERTS_FILE, 'w', encoding='utf-8') as f:
                # Manejar tipos numéricos de numpy si es necesario
                def serialize_numpy(obj):
                     if isinstance(obj, (np.int64, np.float64, np.int32, np.float32)): # Añadir más tipos si es necesario
                          return obj.item() # Convertir a tipo nativo de Python
                     raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


                # Usar default=serialize_numpy para manejar tipos numpy que podrían quedar en los detalles
                json.dump(self.alerts, f, indent=4, ensure_ascii=False, default=serialize_numpy)
            # print(f"DEBUG: Alertas guardadas en {ALERTS_FILE}") # Descomentar para depurar
        except IOError as e:
            print(f"ERROR: No se pudo guardar el archivo de alertas '{ALERTS_FILE}': {e}")
            print(traceback.format_exc())
        except Exception as e:
            print(f"ERROR: Error inesperado al guardar alertas: {e}")
            print(traceback.format_exc())
        # print("DEBUG: <- Saliendo de _save_alerts") # Descomentar para depurar


    # --- MÉTODO mark_alert_reviewed ---
    def mark_alert_reviewed(self, alert_id):
        """Marca una alerta específica como revisada por su ID."""
        alert_updated = False
        found = False
        # Asegurarse de que alert_id es int para la comparación
        if not isinstance(alert_id, int):
            try:
                alert_id = int(alert_id)
            except (ValueError, TypeError):
                print(f"ERROR: ID de alerta inválido recibido: {alert_id}")
                return False # Devolver False si el ID no es válido

        for alert in self.alerts:
            # Usar .get() para acceder al ID de forma segura
            if alert.get('id') == alert_id:
                found = True
                # Usar .get() para acceder al estado 'reviewed' de forma segura
                if not alert.get('reviewed', False): # Usar False como valor por defecto
                    alert['reviewed'] = True
                    alert_updated = True
                    print(f"INFO: Alerta ID {alert_id} marcada como revisada.")
                # else: print(f"INFO: Alerta ID {alert_id} ya estaba revisada.") # Opcional
                break # Salir del bucle una vez encontrada la alerta

        if not found:
            print(f"ERROR: No se encontró alerta con ID {alert_id}.")
            return False # Devuelve False si no se encontró

        if alert_updated:
            self._save_alerts() # Guardar después de actualizar
            return True
        # Si se encontró pero ya estaba revisada
        return False


    # --- MÉTODO update_config ---
    def update_config(self, severity_threshold=None, notify_email=None):
        """Actualiza la configuración de alertas."""
        updated = False
        valid_severities = ['Baja', 'Media', 'Alta', 'Crítica']
        # Validar y actualizar umbral de severidad
        if severity_threshold is not None:
             if isinstance(severity_threshold, str) and severity_threshold in valid_severities:
                 if self.config.get('severity_threshold') != severity_threshold:
                      self.config['severity_threshold'] = severity_threshold
                      print(f"INFO: Umbral severidad actualizado a '{severity_threshold}'"); updated = True
             else:
                  print(f"ERROR: Umbral severidad inválido recibido para actualizar: {severity_threshold}. Debe ser uno de {valid_severities}."); return False

        # Validar y actualizar notificación por email
        if notify_email is not None:
             if isinstance(notify_email, bool):
                   if self.config.get('notify_email') != notify_email:
                        self.config['notify_email'] = notify_email
                        print(f"INFO: Notificación Email {'Activada' if notify_email else 'Desactivada'}."); updated = True
             else:
                   print("ERROR: Valor inválido recibido para notify_email (debe ser True/False)"); return False


        # Nota: Configuración no se guarda persistentemente aquí por defecto.
        # Si quisieras persistirla (ej. en un archivo o BD), deberías añadir
        # una llamada a un método _save_config() aquí o manejarlo externamente.
        # Por ahora, solo actualizamos la instancia en memoria.

        # Devuelve True si al menos una configuración se actualizó
        return updated


    # --- MÉTODO delete_all_alerts ---
    def delete_all_alerts(self):
        """
        Borra TODAS las alertas almacenadas.
        Retorna (bool: success, str: message)
        """
        try:
            count = len(self.alerts)
            self.alerts = [] # La forma más simple si es una lista en memoria

            # Si usaras una base de datos, aquí ejecutarías: DELETE FROM alerts;

            self._save_alerts() # Save the changes after deleting

            # También, si quieres borrar el archivo físico:
            # if os.path.exists(ALERTS_FILE):
            #     os.remove(ALERTS_FILE)
            #     print(f"INFO: Archivo de alertas '{ALERTS_FILE}' eliminado.")

            print(f"INFO: {count} alertas borradas exitosamente.")
            # Asegurarse de reiniciar el contador de IDs si se borran todas
            self._next_id = 1
            return True, f"Se borraron exitosamente {count} alertas."
        except Exception as e:
            # Loggear el error es importante
            print(f"ERROR al borrar todas las alertas: {e}\n{traceback.format_exc()}")
            return False, f"Ocurrió un error al intentar borrar las alertas: {e}"


    # --- MÉTODO manage_rules (Placeholder) ---
    def manage_rules(self): # Placeholder method
        """Gestiona reglas de seguridad (Placeholder)."""
        print("INFO: Accediendo a gestión de reglas (Placeholder).")
        return "Funcionalidad de gestión de reglas no implementada."