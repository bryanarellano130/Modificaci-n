# test_write_permissions.py
import os
import time

test_dir = 'models_test' # Usamos un nombre diferente para no interferir con el original
test_file_path = os.path.join(test_dir, 'test_write.txt')

print(f"--- Iniciando prueba de escritura ---")
print(f"Directorio actual de trabajo: {os.getcwd()}")
print(f"Intentando crear directorio: .\\{test_dir}") # Mostrar ruta relativa

try:
    # Crear el directorio
    os.makedirs(test_dir, exist_ok=True)
    print(f"SUCCESS: Directorio '{test_dir}' creado o ya existe.")

    # Intentar escribir un archivo de prueba
    print(f"Intentando escribir archivo: .\\{test_file_path}") # Mostrar ruta relativa
    with open(test_file_path, 'w') as f:
        f.write(f"Este es un archivo de prueba de escritura creado el {time.ctime()}.\n")
    print(f"SUCCESS: Archivo de prueba '{test_file_path}' escrito exitosamente.")

    # Verificar si el archivo existe
    if os.path.exists(test_file_path):
        print(f"SUCCESS: Verificación: El archivo '{test_file_path}' existe en el sistema de archivos.")
    else:
        print(f"ERROR: Verificación: El archivo '{test_file_path}' NO existe después de intentar escribirlo.")

except PermissionError:
    print(f"ERROR: PermissionError: No tienes permisos para crear directorios o escribir archivos en '{os.getcwd()}'.")
    print("Intenta ejecutar tu terminal o Visual Studio Code 'Como administrador'.")
except FileNotFoundError:
    print(f"ERROR: FileNotFoundError: Una parte de la ruta especificada no existe. Esto es inesperado si el directorio se creó.")
except Exception as e:
    print(f"ERROR: Falló la prueba de escritura debido a un error inesperado: {e}")
    import traceback
    print(traceback.format_exc())

print(f"--- Prueba de escritura completa ---")