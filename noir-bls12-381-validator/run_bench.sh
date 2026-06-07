#!/bin/bash

# Validar que el usuario haya pasado un comando
if [ -z "$1" ]; then
    echo "Error: Debes pasar el comando entre comillas."
    echo "Uso: $0 \"tu comando aqui\""
    echo "Ejemplo: $0 \"nargo compile\""
    exit 1
fi

# Capturar el comando enviado por el usuario
CMD_TO_RUN="$1"

# 1. Configurar nombres de archivos basados en la fecha y hora actual
TIMESTAMP=$(date +"%m%d-%H%M")
# Reemplazar espacios del comando por guiones bajos para el nombre del archivo log
CMD_CLEAN=$(echo "$CMD_TO_RUN" | tr ' ' '_')
LOG_FILE="${CMD_CLEAN}_${TIMESTAMP}.log"
REPORT_FILE="reporte_${CMD_CLEAN}_${TIMESTAMP}.txt"

echo "========================================================="
echo " Iniciando monitoreo de Comando - ${TIMESTAMP}"
echo " Comando a ejecutar: $CMD_TO_RUN"
echo " Logs de salida:     $LOG_FILE"
echo " Reporte de consumo: $REPORT_FILE"
echo "========================================================="

# 2. Ejecutar el comando dinámico midiendo recursos detallados con /usr/bin/time
# Evaluamos la variable $CMD_TO_RUN de forma segura.
# Captura tanto stdout como stderr (2>&1) y lo duplica a la pantalla y al log.

/usr/bin/time -v eval "$CMD_TO_RUN" 2>&1 | tee "$LOG_FILE"
EXIT_CODE=${PIPESTATUS[0]} # Captura el exit code real del comando ejecutado, no el de tee

# 3. Calcular espacio en disco actual del proyecto
DISK_USAGE=$(du -sh . | cut -f1)

# 4. Generar el reporte final estructurado
{
    echo "========================================================="
    echo "         REPORTE DE EJECUCIÓN DE TRABAJO"
    echo "========================================================="
    echo "Fecha/Hora:  $(date)"
    echo "Comando:     $CMD_TO_RUN"
    if [ $EXIT_CODE -eq 0 ]; then
        echo "Estado final: EXCELENTE (Código 0 - Terminó con éxito)"
    else
        echo "Estado final: FALLIDO (Código $EXIT_CODE)"
        echo "--> El proceso falló o fue interrumpido."
        echo "--> Revisa las últimas líneas de $LOG_FILE para ver qué pasó."
    fi
    echo "Almacenamiento total del proyecto tras finalizar: $DISK_USAGE"
    echo "========================================================="
    echo "Detalles de Recursos y Tiempo de CPU:"
} > "$REPORT_FILE"

echo -e "\n[✔] El proceso ha concluido. Detalles guardados en: $REPORT_FILE"