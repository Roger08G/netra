# Criterio de producción 1.0.0

## Incluido y verificable

- versión 1.0.0 coherente entre CLI, motor, metadata y artefacto;
- protocolo JSON/NDJSON estricto y eventos asociados a una petición;
- alcance IPv4 privado o link-local, exclusiones y límite activo de 4096 direcciones;
- cancelación sin publicación de un JSON parcial;
- errores de recolectores reflejados en `coverage.issues` cuando la ejecución puede continuar;
- secretos SNMP fuera de configuración, eventos, artefactos y entorno hijo;
- renderizado de datos no confiables y CSP sin dependencias de red;
- wheel Windows con motor incluido, etiqueta de plataforma, instalación limpia y SHA-256.

## Validación obligatoria por build

```powershell
.\scripts\build-windows.ps1
```

La build solo es aceptable si pasan pruebas Go, `go vet`, pruebas Python, inspección del wheel, instalación en un venv limpio y `netra doctor --json`.

## Declaraciones que 1.0.0 no hace

- No afirma cobertura total ni que una red sea segura.
- No convierte FDB en prueba automática de cableado directo.
- No garantiza compatibilidad SNMP con hardware que no se haya probado.
- No realiza auditoría de vulnerabilidades, explotación, lectura de banners ni medición de rendimiento.

## Antes de distribuir públicamente

La build técnica puede usarse internamente. Una publicación a terceros necesita decisiones del propietario que no deben inventarse en código: licencia, titular/canal privado de seguridad, firma del binario o del instalador y matriz de switches realmente probados.
