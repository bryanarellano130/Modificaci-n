# threat_simulator.py
import pandas as pd
import numpy as np
import datetime

class ThreatSimulator:
    """
    Simula tráfico de red y diferentes tipos de ataques cibernéticos (Placeholder).
    """

    def __init__(self):
        """Inicializa el simulador y el historial de simulaciones."""
        self.simulation_history = [] # Almacena metadatos de simulaciones pasadas
        print("INFO: ThreatSimulator inicializado.") # Puedes usar logging

    def run_simulation(self, config):
        """
        Ejecuta una simulación basada en la configuración proporcionada.

        Args:
            config (dict): Un diccionario con los parámetros de la simulación.
                           Ej: {'duration': 60, 'intensity': 5, 'attacks': ['DDoS', 'Scan']}

        Returns:
            pandas.DataFrame: Un DataFrame que contiene los datos de tráfico simulados.
                              Retorna un DataFrame vacío si la configuración es inválida.
                              O Lanza una excepción si ocurre un error grave.
        """
        duration = config.get('duration', 60)
        intensity = config.get('intensity', 5) # Nivel de 1 a 10
        attack_types = config.get('attacks', ['DDoS', 'Scan']) # Tipos de ataque a simular

        # Validaciones básicas de configuración (pueden estar en la ruta Flask también)
        if not isinstance(duration, int) or duration <= 0:
             print("ERROR: Duración inválida para la simulación.")
             # Considera lanzar una excepción aquí en lugar de devolver DF vacío
             # raise ValueError("Duración inválida para la simulación.")
             return pd.DataFrame()
        if not isinstance(intensity, int) or not (1 <= intensity <= 10) :
             print("ERROR: Intensidad inválida (debe ser entre 1 y 10).")
             # raise ValueError("Intensidad inválida (debe ser entre 1 y 10).")
             return pd.DataFrame()

        print(f"INFO: Ejecutando simulación - Duración: {duration}s, Intensidad: {intensity}, Ataques: {attack_types}")

        # --- LÓGICA DE SIMULACIÓN (PLACEHOLDER - CORREGIDA) ---
        # ** ¡IMPORTANTE! Reemplaza esta sección con tu lógica real de simulación **

        # Calcular número de registros (ej: 10 eventos por segundo simulado)
        num_records = duration * 10
        # Probabilidad base de que un registro sea un ataque (ajustado por intensidad)
        attack_probability = (intensity / 15.0) # Ajusta este factor (0.06 a 0.66)

        # Generar Timestamps
        start_time = pd.Timestamp.now(tz='UTC') # Usar UTC es buena práctica
        timestamps = pd.to_datetime(start_time + np.arange(num_records) * np.timedelta64(100, 'ms'))

        # Generar IPs (simplista)
        src_ips = [f"192.168.{np.random.randint(1, 3)}.{np.random.randint(10, 100)}" for _ in range(num_records)]
        dst_ips = [f"10.0.{np.random.randint(0, 2)}.{np.random.randint(1, 255)}" for _ in range(num_records)]

        # Generar Protocolos
        protocols = np.random.choice(['TCP', 'UDP', 'ICMP'], size=num_records, p=[0.6, 0.3, 0.1])

        # --- **CORRECCIÓN UnboundLocalError: Crear diccionario en 2 pasos** ---

        # Paso 1: Crear diccionario 'data' solo con valores independientes
        data = {
            'src_ip': src_ips,
            'dst_ip': dst_ips,
            'protocol': protocols,
            'flow_duration': np.random.randint(100, 90000000, size=num_records), # Microsegundos
            'tot_fwd_pkts': np.random.randint(1, 50, size=num_records), # Base para cálculos posteriores
            'tot_bwd_pkts': np.random.randint(0, 50, size=num_records), # Base para cálculos posteriores
            'fwd_pkt_len_mean': np.random.rand(num_records) * 150,
            'fwd_pkt_len_std': np.random.rand(num_records) * 200,
            'bwd_pkt_len_mean': np.random.rand(num_records) * 120,
            'flow_iat_mean': np.random.rand(num_records) * 1000000, # Microsegundos
            'flow_iat_std': np.random.rand(num_records) * 500000,
            'fwd_iat_tot': np.random.rand(num_records) * 80000000,
            'pkt_len_mean': np.random.rand(num_records) * 100,
            'pkt_len_std': np.random.rand(num_records) * 150,
            'pkt_len_var': np.random.rand(num_records) * 22500,
            'downup_ratio': np.random.rand(num_records) * 3,
            'pkt_size_avg': np.random.rand(num_records) * 100,
            'init_win_byts_fwd': np.random.choice([8192, 65535, 4096, 0], size=num_records),
            'init_win_byts_bwd': np.random.choice([8192, 65535, 4096, 0, -1], size=num_records), # -1 puede indicar no aplicable
            'active_mean': np.random.rand(num_records) * 100000,
            'idle_mean': np.random.rand(num_records) * 10000000,
            # ... Añade aquí OTRAS columnas que NO dependan de otras generadas aquí ...
        }

        # Paso 2: Añadir columnas dependientes al diccionario 'data' existente
        # Asegurarse que las columnas base existen antes de usarlas
        if 'tot_fwd_pkts' in data:
            # Usar directamente el array numpy del diccionario 'data'
            data['totlen_fwd_pkts'] = np.random.randint(0, 15000, size=num_records) * data['tot_fwd_pkts'].clip(min=1) # clip(min=1) evita multiplicar por 0 si tot_fwd_pkts puede ser 0
            data['fwd_header_len'] = np.random.choice([20, 32, 40, 60], size=num_records) * data['tot_fwd_pkts'] # Asume TCP/IP header size * num packets
        else:
             print("WARN: 'tot_fwd_pkts' no encontrado para cálculos dependientes en simulación.")
             data['totlen_fwd_pkts'] = 0 # Valor por defecto o manejo de error
             data['fwd_header_len'] = 0

        if 'tot_bwd_pkts' in data:
            # Usar directamente el array numpy del diccionario 'data'
            data['totlen_bwd_pkts'] = np.random.randint(0, 15000, size=num_records) * data['tot_bwd_pkts'].clip(min=0) # Bwd puede ser 0 paquetes
            data['bwd_header_len'] = np.random.choice([20, 32, 40, 60], size=num_records) * data['tot_bwd_pkts']
        else:
             print("WARN: 'tot_bwd_pkts' no encontrado para cálculos dependientes en simulación.")
             data['totlen_bwd_pkts'] = 0
             data['bwd_header_len'] = 0

        # --- Fin Corrección ---

        # Crear DataFrame DESPUÉS de que el diccionario 'data' esté completo
        try:
            resultado_simulacion = pd.DataFrame(data)
            # Añadir timestamp como columna (mejor práctica que como índice a veces)
            resultado_simulacion['timestamp'] = timestamps
        except Exception as e_df:
             print(f"ERROR: Creando DataFrame de simulación: {e_df}")
             print(traceback.format_exc())
             return pd.DataFrame() # Devolver DF vacío si falla la creación

        # Asignar Etiquetas (Simulación de Ataques)
        is_attack = np.random.rand(num_records) < attack_probability
        attack_labels = np.random.choice(attack_types, size=num_records) # Asigna un tipo a cada posible ataque
        resultado_simulacion['label'] = np.where(is_attack, attack_labels, 'BENIGN')

        # --- FIN LÓGICA PLACEHOLDER ---

        print(f"SUCCESS: Simulación completada. Generados {len(resultado_simulacion)} registros.")
        print("Distribución de etiquetas generadas:")
        # Usar .get() por si 'label' no se generó por algún error previo
        print(resultado_simulacion.get('label', pd.Series(dtype=str)).value_counts())

        # Guardar metadatos en el historial
        history_entry = {
            "config": config,
            "timestamp": datetime.datetime.now().isoformat(timespec='seconds'),
            "num_records": len(resultado_simulacion),
            "label_distribution": resultado_simulacion.get('label', pd.Series(dtype=str)).value_counts().to_dict()
        }
        self.simulation_history.append(history_entry)

        return resultado_simulacion

    def get_history(self):
        """
        Devuelve el historial de metadatos de las simulaciones ejecutadas.

        Returns:
            list: Una lista de diccionarios, donde cada diccionario contiene
                  los metadatos de una simulación.
        """
        return self.simulation_history

# Sección para pruebas directas (opcional)
if __name__ == '__main__':
    print("Probando ThreatSimulator...")
    simulator = ThreatSimulator()
    test_config = {'duration': 5, 'intensity': 7, 'attacks': ['DDoS', 'PortScan']}
    df_result = simulator.run_simulation(test_config)

    print("\n--- Resultado de la Simulación (Prueba) ---")
    if not df_result.empty:
        print(f"Dimensiones del DataFrame: {df_result.shape}")
        print("Primeras 5 filas:")
        print(df_result.head())
        print("\nInformación del DataFrame:")
        df_result.info()
    else:
        print("La simulación de prueba no generó datos o falló.")

    print("\n--- Historial de Simulación (Prueba) ---")
    print(simulator.get_history())