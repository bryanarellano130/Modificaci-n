// static/js/main.js
console.log("CyberSystem Main JS Loaded - Timestamp:", new Date().toLocaleTimeString());

// Función de confirmación para acciones potencialmente destructivas
function addConfirmationChecks() {
    const confirmButtons = document.querySelectorAll('.delete-action-button'); // Busca botones con esta clase
    confirmButtons.forEach(button => {
        // Evitar añadir el listener múltiples veces si la función se llama de nuevo
        if (!button.dataset.confirmListenerAdded) {
            button.addEventListener('click', (event) => {
                const message = button.dataset.confirmMessage || '¿Estás seguro de que quieres realizar esta acción? Es irreversible.';
                if (!confirm(message)) {
                    event.preventDefault(); // Cancela el evento (ej: envío de formulario) si el usuario dice "Cancelar"
                    console.log("Acción cancelada por el usuario.");
                }
            });
            button.dataset.confirmListenerAdded = 'true'; // Marcar que el listener fue añadido
        }
    });
    // Comentar o descomentar para depuración
    // console.log(`Confirmation listeners potentially attached to ${confirmButtons.length} buttons.`);
}

// Función para inicializar elementos interactivos
function initializePage() {
    // console.log("Initializing page elements..."); // Comentar o descomentar para depuración
    addConfirmationChecks();

    // Ejemplo: Mostrar/Ocultar secciones (si usas data-toggle)
    const toggleButtons = document.querySelectorAll('[data-toggle]');
    toggleButtons.forEach(button => {
        if (!button.dataset.toggleListenerAdded) {
             button.addEventListener('click', () => {
                const targetId = button.getAttribute('data-toggle');
                const targetElement = document.getElementById(targetId);
                if (targetElement) {
                    const isHidden = targetElement.style.display === 'none' || targetElement.offsetParent === null; // Check visibility
                    targetElement.style.display = isHidden ? 'block' : 'none';
                    // Actualizar texto del botón si se definen atributos data-toggle-show-text / data-toggle-hide-text
                    button.textContent = isHidden ? (button.dataset.toggleHideText || 'Ocultar') : (button.dataset.toggleShowText || 'Mostrar');
                }
            });
            button.dataset.toggleListenerAdded = 'true';
        }
    });
    // console.log(`Toggle listeners attached to ${toggleButtons.length} buttons.`);

    // --- Lógica AJAX para el formulario de detección ---
    // --- ASEGÚRATE QUE ESTA SECCIÓN ESTÉ COMENTADA ASÍ ---

    /* // <--- INICIO DEL BLOQUE COMENTADO

    const detectionForm = document.getElementById('detection-form');
    const resultsArea = document.getElementById('detection-results-area');
    const loadingIndicator = document.getElementById('loading-indicator');

    if (detectionForm && resultsArea && loadingIndicator) {
        if (!detectionForm.dataset.ajaxListenerAdded) {
            detectionForm.addEventListener('submit', async (event) => {
                event.preventDefault(); // Evita el envío normal
                console.log("Detection form submitted via AJAX");
                loadingIndicator.style.display = 'block'; // Muestra "Cargando..."
                resultsArea.innerHTML = ''; // Limpia resultados anteriores

                const formData = new FormData(detectionForm);

                try {
                    // NECESITAS CREAR la ruta '/run_detection_ajax' en app.py que devuelva JSON
                    const response = await fetch('/run_detection_ajax', {
                        method: 'POST',
                        body: formData
                    });

                    // Pequeña pausa artificial para que se vea el "cargando"
                    await new Promise(resolve => setTimeout(resolve, 300));
                    loadingIndicator.style.display = 'none'; // Oculta "Cargando..."

                    if (!response.ok) {
                        let errorMsg = `Error HTTP ${response.status}`;
                        try { const errorData = await response.json(); errorMsg = errorData.message || errorMsg; } catch(e) {}
                        throw new Error(errorMsg);
                    }

                    const results = await response.json(); // Espera respuesta JSON
                    console.log("AJAX Response:", results);

                    if (results.success) {
                        let html = `<h3>Resultados de Detección (${results.data_info || ''})</h3>`;
                        // ... Construir HTML con resultados ...
                        // Ejemplo:
                        if(results.metrics && results.metrics.accuracy !== null) {
                           html += `<p><strong>Accuracy:</strong> ${(results.metrics.accuracy * 100).toFixed(2)}%</p>`;
                        }
                        if (results.plot_url) {
                           html += `<h4>Matriz de Confusión:</h4><img src="${results.plot_url}" alt="Matriz de Confusión" style="max-width: 400px; height: auto; border: 1px solid #ccc;">`;
                        }
                         if (results.report_html) {
                             html += `<h4>Reporte de Clasificación:</h4> ${results.report_html}`;
                         }
                        if (results.data_head_html) {
                             html += `<h4>Primeras Filas Detectadas:</h4> ${results.data_head_html}`;
                        }
                        resultsArea.innerHTML = html;
                    } else {
                        resultsArea.innerHTML = `<div class="alert alert-error">Error en la detección: ${results.message || 'Error desconocido'}</div>`;
                    }

                } catch (error) {
                    console.error('Error en AJAX:', error);
                    loadingIndicator.style.display = 'none';
                    resultsArea.innerHTML = `<div class="alert alert-error">Error al procesar la solicitud: ${error.message}</div>`;
                }
            });
            detectionForm.dataset.ajaxListenerAdded = 'true';
            console.log("AJAX listener attached to detection form.");
        }
    } else {
        // console.log("Detection form or results area not found, skipping AJAX setup.");
    }

    */ // <--- FIN DEL BLOQUE COMENTADO

    // --- Fin lógica AJAX ---

}

// Ejecutar las inicializaciones cuando el DOM esté listo
if (document.readyState === 'loading') { // Si aún está cargando
    document.addEventListener('DOMContentLoaded', initializePage);
} else { // Si ya cargó
    initializePage();
}

// Si usas alguna librería que cargue contenido dinámicamente (ej: htmx),
// puede que necesites volver a llamar a initializePage() después de que
// el nuevo contenido sea insertado en el DOM.