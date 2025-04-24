# admin_manager.py
import os # Necesario para os.path.exists
import json # Necesario para json.load/dump
import datetime # Necesario para logs de ejemplo
import traceback # Necesario para imprimir tracebacks de errores

# Importa tu clase ThreatDetector (la instancia se pasa al constructor)
# from threat_detector import ThreatDetector # No la importamos aquí directamente

CONFIG_FILE = 'system_config.json' # Nombre del archivo de configuración para persistencia (Opcional)

class AdminManager:
    """
    Gestiona la configuración del sistema y tareas administrativas.
    También maneja la persistencia de la configuración básica (umbral GLM).
    """

    def __init__(self, detector_instance):
        """
        Inicializa el gestor de administración.

        Args:
            detector_instance (ThreatDetector): Una instancia del ThreatDetector
                                                para poder interactuar con él (ej: cambiar umbral).
        """
        print("INFO: AdminManager inicializado.")
        self.detector_ref = detector_instance # Guardar una referencia a la instancia del detector

        # Cargar configuración existente o usar valores por defecto
        self.system_config = self._load_config()

        # Asegurarse de que el umbral GLM en la config refleje el del detector actual al inicio
        # CORREGIDO: Usar self.detector_ref.prediction_threshold
        if self.detector_ref and hasattr(self.detector_ref, 'prediction_threshold'):
             # Usar el umbral del detector como fuente de verdad si el detector es válido
             self.system_config['glm_threshold'] = self.detector_ref.prediction_threshold
             print(f"DEBUG: Sincronizando umbral GLM en config con detector: {self.system_config['glm_threshold']}")
        else:
             # Si el detector no es válido al inicio, usar el umbral cargado o por defecto
             if 'glm_threshold' not in self.system_config:
                  self.system_config['glm_threshold'] = 0.7 # Umbral por defecto si no hay detector y no hay config previa
                  print(f"WARNING: Instancia de ThreatDetector no válida al inicio. Usando umbral por defecto: {self.system_config['glm_threshold']}.")
             else:
                  print(f"WARNING: Instancia de ThreatDetector no válida al inicio. Usando umbral cargado: {self.system_config['glm_threshold']}.")


        print(f"INFO: Configuración inicial del sistema: {self.system_config}")
        self._save_config() # Guardar la configuración inicial o actualizada (persistencia)


    def _load_config(self):
        """Carga la configuración del sistema desde un archivo JSON."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    print(f"INFO: Configuración del sistema cargada desde {CONFIG_FILE}")
                    # Asegurarse de que las claves esperadas existen en la config cargada
                    if 'glm_threshold' not in config:
                        config['glm_threshold'] = 0.7 # Fallback si falta
                        print(f"WARNING: 'glm_threshold' no encontrado en config cargada. Usando por defecto.")
                    # Agrega validaciones para otras claves aquí si es necesario
                    return config
            except Exception as e:
                print(f"ERROR al cargar la configuración del sistema desde {CONFIG_FILE}: {e}\n{traceback.format_exc()}")
                print("INFO: Usando configuración por defecto.")
                # Fallback a configuración por defecto si falla la carga
        else:
            print(f"INFO: Archivo de configuración del sistema '{CONFIG_FILE}' no encontrado. Usando configuración por defecto.")

        # Configuración por defecto si el archivo no existe o falló la carga
        return {
            'glm_threshold': 0.7 # Umbral por defecto
            # Agrega otras configuraciones por defecto aquí si las tienes
        }

    def _save_config(self):
        """Guarda la configuración actual del sistema a un archivo JSON."""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.system_config, f, indent=4)
            print(f"INFO: Configuración del sistema guardada en {CONFIG_FILE}")
        except Exception as e:
            print(f"ERROR al guardar la configuración del sistema en {CONFIG_FILE}: {e}\n{traceback.format_exc()}")


    def update_glm_threshold(self, new_threshold):
        """Actualiza el umbral de predicción en el detector y en la configuración."""
        if self.detector_ref is None:
             return False, "Error: No hay referencia al detector para actualizar el umbral."

        # Llama al método del detector para validarlo y aplicarlo
        success = self.detector_ref.set_threshold(new_threshold)
        if success:
            # Si el detector lo aceptó, actualiza nuestra copia en config
            # CORREGIDO: Leer el umbral actualizado del detector usando prediction_threshold
            self.system_config['glm_threshold'] = self.detector_ref.prediction_threshold
            self._save_config() # Guardar el cambio
            msg = f"Umbral de decisión GLM actualizado a {self.system_config['glm_threshold']:.3f}"
            print(f"INFO: {msg}")
            return True, msg
        else:
            # El detector ya imprimió un error, solo devolvemos mensaje genérico
            msg = f"No se pudo actualizar el umbral a {new_threshold}. Valor inválido."
            # Si el detector tiene un mensaje de error específico, podrías intentar recuperarlo
            # ej: msg = getattr(self.detector_ref, '_last_error_msg', msg)
            print(f"WARNING: {msg}")
            return False, msg


    def get_system_logs(self, max_lines=50):
        """
        Obtiene registros simulados del sistema.
        (Placeholder - Debería leer de un archivo de log real).

        Args:
            max_lines (int): Número máximo de líneas a devolver (no implementado aquí).

        Returns:
            str: Un string multi-línea con los logs simulados.
        """
        print("INFO: Obteniendo registros simulados del sistema (Placeholder).")
        # En una implementación real, aquí leerías las últimas N líneas de un archivo
        # de log configurado con el módulo 'logging' de Python.
        # También podrías obtener el número de alertas del alert_manager si tienes acceso a él.
        # Asegurarse de que el umbral mostrado en el log simulado también use el valor actual
        current_threshold_display = self.system_config.get('glm_threshold', 'N/A')
        if isinstance(current_threshold_display, (int, float)):
            current_threshold_display = f"{current_threshold_display:.2f}"

        log_ejemplo = f"""
[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: Simulando logs del sistema.
[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: Flask app inicializada. Modo Debug: True.
[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: DataManager inicializado.
[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: ThreatSimulator inicializado.
[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: ThreatDetector inicializado. Umbral: {current_threshold_display}
[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: AlertManager inicializado.
[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: AdminManager inicializado.
[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: Ruta '/' accedida.
[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: Datos cargados/preprocesados. Filas: {len(self.detector_ref.data_manager_ref.get_processed_data()) if self.detector_ref and self.detector_ref.data_manager_ref and self.detector_ref.data_manager_ref.get_processed_data() is not None else 'N/A'}.
[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: Reentrenamiento solicitado.
[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] SUCCESS: Modelo reentrenado y guardado.
[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: Detección en datos preprocesados iniciada.
[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] SUCCESS: Detección completada. Ataques detectados: [Simulado]. Alertas generadas: [Simulado].
[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: Acceso a página de detección. Métricas de evaluación mostradas (Accuracy: [Simulado]).
[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: Umbral GLM actualizado a [Nuevo Valor Simulado].
        """
        # Mejorar la simulación de logs para que refleje eventos reales si es posible,
        # por ejemplo, leyendo del historial de detecciones.
        # Por ahora, es solo un string estático mejorado.
        return log_ejemplo.strip() # Elimina espacios extra al inicio/final


    # NOTA IMPORTANTE: El método trigger_retraining en AdminManager ya NO se usa
    # para iniciar el reentrenamiento REAL. Esa lógica está en app.py ahora.
    # Puedes eliminar el método trigger_retraining de AdminManager o mantenerlo
    # como un placeholder obsoleto si no lo estás llamando en app.py.
    # Según la salida anterior, la ruta /admin/action en app.py llama directamente
    # a detector.train_and_save_model, no a admin_manager.trigger_retraining.


    def get_config(self):
        """
        Devuelve la configuración actual del sistema gestionada por AdminManager.
        Sincroniza el umbral GLM con el detector antes de devolver.

        Returns:
            dict: El diccionario self.system_config.
        """
        # Asegurarse que el umbral esté sincronizado con el detector por si acaso
        # CORREGIDO: Usar self.detector_ref.prediction_threshold aquí también
        if self.detector_ref and hasattr(self.detector_ref, 'prediction_threshold'):
            self.system_config['glm_threshold'] = self.detector_ref.prediction_threshold
            print(f"DEBUG: Sincronizando umbral GLM en config para get_config: {self.system_config['glm_threshold']}")
        elif 'glm_threshold' not in self.system_config:
             # Fallback si el detector no es válido y la clave no está en config
             self.system_config['glm_threshold'] = 0.7 # Valor por defecto

        return self.system_config

    # Puedes añadir otros métodos de administración aquí si es necesario
    # def delete_detection_history(self): ...
    # def clear_alerts(self): ...