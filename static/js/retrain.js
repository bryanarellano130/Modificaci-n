document.addEventListener('DOMContentLoaded', function() {
    const startBtn = document.getElementById('startRetrainBtn');
    const statusMessage = document.getElementById('statusMessage');
    const progressBarContainer = document.getElementById('progressBarContainer');
    const progressBar = document.getElementById('progressBar');
    const statusLog = document.getElementById('statusLog');
    let taskId = null;
    let intervalId = null;

    startBtn.addEventListener('click', function() {
        // Deshabilitar botón y mostrar inicio
        startBtn.disabled = true;
        statusMessage.textContent = 'Iniciando reentrenamiento...';
        statusMessage.className = 'alert alert-info'; // Cambiar clase para estilo
        progressBarContainer.style.display = 'block';
        progressBar.style.width = '0%';
        progressBar.textContent = '0%';
        statusLog.textContent = ''; // Limpiar log anterior

        // (Opcional: obtener data_path del input si se implementa subida)
        // const dataPath = document.getElementById('dataInput').value;

        // Llamar a la ruta de inicio en el backend
        fetch('/retrain/start', { // Asegúrate que la URL sea correcta
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                // Incluir CSRF token si usas Flask-WTF CSRF protection
            },
            // body: JSON.stringify({ data_path: dataPath }) // Enviar data_path si es dinámico
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`Error del servidor: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.status === 'PENDING' && data.task_id) {
                taskId = data.task_id;
                statusMessage.textContent = `Tarea iniciada (ID: ${taskId}). Esperando progreso...`;
                statusLog.textContent = 'Tarea en cola...\n';
                // Empezar a consultar el estado periódicamente
                intervalId = setInterval(checkStatus, 3000); // Consultar cada 3 segundos
            } else {
                throw new Error(data.message || 'Respuesta inesperada al iniciar tarea.');
            }
        })
        .catch(error => {
            console.error('Error al iniciar reentrenamiento:', error);
            statusMessage.textContent = `Error al iniciar: ${error.message}`;
            statusMessage.className = 'alert alert-danger';
            progressBarContainer.style.display = 'none';
            startBtn.disabled = false; // Rehabilitar botón en caso de error inicial
        });
    });

    function checkStatus() {
        if (!taskId) return;

        fetch(`/retrain/status/${taskId}`) // Asegúrate que la URL sea correcta
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Error del servidor al consultar estado: ${response.status}`);
                }
                return response.json();
             })
            .then(data => {
                // Actualizar UI con el estado recibido
                statusLog.textContent = data.log || ''; // Mostrar logs
                statusLog.scrollTop = statusLog.scrollHeight; // Auto-scroll al final

                const progress = data.progress || 0;
                progressBar.style.width = `${progress}%`;
                progressBar.textContent = `${progress}%`;
                progressBar.setAttribute('aria-valuenow', progress);


                if (data.status === 'RUNNING') {
                    statusMessage.textContent = `Procesando... (${progress}%)`;
                    statusMessage.className = 'alert alert-info';
                    progressBar.classList.add('progress-bar-animated');
                } else if (data.status === 'SUCCESS') {
                    statusMessage.textContent = '¡Reentrenamiento completado con éxito!';
                    statusMessage.className = 'alert alert-success';
                    progressBar.classList.remove('progress-bar-animated');
                    clearInterval(intervalId); // Detener consultas
                    startBtn.disabled = false; // Rehabilitar botón
                } else if (data.status === 'FAILURE') {
                    statusMessage.textContent = 'Error durante el reentrenamiento.';
                    statusMessage.className = 'alert alert-danger';
                    progressBar.classList.remove('progress-bar-animated');
                    progressBar.classList.add('bg-danger'); // Poner barra roja
                    clearInterval(intervalId); // Detener consultas
                    startBtn.disabled = false; // Rehabilitar botón
                } else if (data.status === 'PENDING') {
                     statusMessage.textContent = `Tarea en cola... (ID: ${taskId})`;
                     statusMessage.className = 'alert alert-secondary';
                } else {
                    // Estado desconocido o tarea no encontrada
                    statusMessage.textContent = `Estado desconocido: ${data.status || 'N/A'}`;
                    statusMessage.className = 'alert alert-warning';
                    // Considera detener las consultas si el ID es desconocido
                    // clearInterval(intervalId);
                    // startBtn.disabled = false;
                }
            })
            .catch(error => {
                console.error('Error al consultar estado:', error);
                statusMessage.textContent = `Error al consultar estado: ${error.message}`;
                statusMessage.className = 'alert alert-danger';
                // Considera detener las consultas si hay errores repetidos
                // clearInterval(intervalId);
                // startBtn.disabled = false;
            });
    }
});