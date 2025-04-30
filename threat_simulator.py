# threat_simulator.py
import pandas as pd
import numpy as np
import datetime
import traceback # Añadido por si acaso para debug futuro

class ThreatSimulator:
    """
    Simula tráfico de red y diferentes tipos de ataques cibernéticos (Placeholder).
    """

    def __init__(self):
        """Inicializa el simulador y el historial de simulaciones."""
        # --- Nombre correcto de la variable de historial ---
        self.simulation_history = [] # Almacena metadatos de simulaciones pasadas
        # --- Fin corrección ---
        print("INFO: ThreatSimulator inicializado.") # Puedes usar logging

    def run_simulation(self, config):
        """
        Ejecuta una simulación basada en la configuración proporcionada.
        (Tu lógica de simulación existente aquí - sin cambios necesarios en esta función)
        """
        duration = config.get('duration', 60)
        intensity = config.get('intensity', 5) # Nivel de 1 a 10
        attack_types = config.get('attacks', ['DDoS', 'Scan'])

        if not isinstance(duration, int) or duration <= 0:
             print("ERROR: Duración inválida.")
             return pd.DataFrame() # Devuelve DF vacío
        if not isinstance(intensity, int) or not (1 <= intensity <= 10) :
             print("ERROR: Intensidad inválida.")
             return pd.DataFrame()

        print(f"INFO: Ejecutando simulación - Duración: {duration}s, Intensidad: {intensity}, Ataques: {attack_types}")

        # --- LÓGICA DE SIMULACIÓN (PLACEHOLDER - TU CÓDIGO EXISTENTE) ---
        num_records = duration * 10
        attack_probability = (intensity / 15.0)
        start_time = pd.Timestamp.now(tz='UTC')
        timestamps = pd.to_datetime(start_time + np.arange(num_records) * np.timedelta64(100, 'ms'))
        src_ips = [f"192.168.{np.random.randint(1, 3)}.{np.random.randint(10, 100)}" for _ in range(num_records)]
        dst_ips = [f"10.0.{np.random.randint(0, 2)}.{np.random.randint(1, 255)}" for _ in range(num_records)]
        protocols = np.random.choice(['TCP', 'UDP', 'ICMP'], size=num_records, p=[0.6, 0.3, 0.1])

        data = {
            'src_ip': src_ips,'dst_ip': dst_ips,'protocol': protocols,
            'flow_duration': np.random.randint(100, 90000000, size=num_records),
            'tot_fwd_pkts': np.random.randint(1, 50, size=num_records),
            'tot_bwd_pkts': np.random.randint(0, 50, size=num_records),
            'fwd_pkt_len_mean': np.random.rand(num_records) * 150,
            'fwd_pkt_len_std': np.random.rand(num_records) * 200,
            'bwd_pkt_len_mean': np.random.rand(num_records) * 120,
            'flow_iat_mean': np.random.rand(num_records) * 1000000,
            'flow_iat_std': np.random.rand(num_records) * 500000,
            'fwd_iat_tot': np.random.rand(num_records) * 80000000,
            'pkt_len_mean': np.random.rand(num_records) * 100,
            'pkt_len_std': np.random.rand(num_records) * 150,
            'pkt_len_var': np.random.rand(num_records) * 22500,
            'downup_ratio': np.random.rand(num_records) * 3,
            'pkt_size_avg': np.random.rand(num_records) * 100,
            'init_win_byts_fwd': np.random.choice([8192, 65535, 4096, 0], size=num_records),
            'init_win_byts_bwd': np.random.choice([8192, 65535, 4096, 0, -1], size=num_records),
            'active_mean': np.random.rand(num_records) * 100000,
            'idle_mean': np.random.rand(num_records) * 10000000,
        }
        if 'tot_fwd_pkts' in data:
            data['totlen_fwd_pkts'] = np.random.randint(0, 15000, size=num_records) * data['tot_fwd_pkts'].clip(min=1)
            data['fwd_header_len'] = np.random.choice([20, 32, 40, 60], size=num_records) * data['tot_fwd_pkts']
        else: data['totlen_fwd_pkts'], data['fwd_header_len'] = 0, 0
        if 'tot_bwd_pkts' in data:
            data['totlen_bwd_pkts'] = np.random.randint(0, 15000, size=num_records) * data['tot_bwd_pkts'].clip(min=0)
            data['bwd_header_len'] = np.random.choice([20, 32, 40, 60], size=num_records) * data['tot_bwd_pkts']
        else: data['totlen_bwd_pkts'], data['bwd_header_len'] = 0, 0

        try:
            resultado_simulacion = pd.DataFrame(data)
            resultado_simulacion['timestamp'] = timestamps
        except Exception as e_df:
            print(f"ERROR: Creando DataFrame sim: {e_df}")
            return pd.DataFrame()

        is_attack = np.random.rand(num_records) < attack_probability
        attack_labels = np.random.choice(attack_types if attack_types else ['Generic Attack'], size=num_records)
        resultado_simulacion['label'] = np.where(is_attack, attack_labels, 'BENIGN')
        # --- FIN LÓGICA PLACEHOLDER ---

        print(f"SUCCESS: Simulación completada. Generados {len(resultado_simulacion)} registros.")
        print("Distribución de etiquetas generadas:")
        print(resultado_simulacion.get('label', pd.Series(dtype=str)).value_counts())

        # ¡ESTA PARTE YA NO SE LLAMA DESDE AQUÍ, se llama desde app.py!
        # history_entry = { ... }
        # self.add_to_history(history_entry) # <-- Ya no va aquí

        return resultado_simulacion

    # --- MÉTODO add_to_history CORREGIDO ---
    def add_to_history(self, simulation_info):
        """
        Añade info de simulación al historial interno.
        (Llamado desde app.py DESPUÉS de guardar el archivo)
        """
        if isinstance(simulation_info, dict):
             # --- CORRECCIÓN AQUÍ ---
            self.simulation_history.append(simulation_info) # Usar simulation_history
             # --- FIN CORRECCIÓN ---
            print(f"DEBUG: Simulación añadida al historial del simulador (total: {len(self.simulation_history)}).")
        else:
            print("WARN: add_to_history recibió información no válida (no es dict).")

    # --- MÉTODO get_history CORREGIDO ---
    def get_history(self):
        """ Devuelve el historial de simulaciones ejecutadas. """
        # --- CORRECCIÓN AQUÍ ---
        if not hasattr(self, 'simulation_history'): # Chequeo extra por si acaso
             self.simulation_history = []
        return list(self.simulation_history) # Usar simulation_history
         # --- FIN CORRECCIÓN ---

# Sección para pruebas directas (opcional)
if __name__ == '__main__':
    print("Probando ThreatSimulator...")
    simulator = ThreatSimulator()
    test_config = {'duration': 5, 'intensity': 7, 'attacks': ['DDoS', 'PortScan']}
    df_result = simulator.run_simulation(test_config)
    # Añadir al historial manualmente para probar los métodos corregidos
    if not df_result.empty:
         sim_info_test = {
             'config': test_config,
             'timestamp': datetime.datetime.now().isoformat(timespec='seconds'),
             'num_records': len(df_result),
             'label_distribution': df_result['label'].value_counts().to_dict(),
             'filepath': 'prueba_no_guardada.pkl' # Placeholder
         }
         simulator.add_to_history(sim_info_test)

    print("\n--- Resultado de la Simulación (Prueba) ---")
    if not df_result.empty:
        print(f"Dimensiones: {df_result.shape}")
        print("Head:\n", df_result.head())
    else:
        print("Simulación de prueba no generó datos.")

    print("\n--- Historial de Simulación (Prueba) ---")
    print(simulator.get_history())