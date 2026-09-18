# Seguridad

## Modelo operativo

Netra se ejecuta localmente y no requiere cuenta. No incluye telemetría ni envía artefactos a servicios externos. Los resultados pueden contener direcciones IP, nombres y MAC de la red; deben tratarse como información sensible.

Utiliza Netra solo sobre redes propias o con autorización expresa. Mantén los planes de alcance, configuraciones SNMP y artefactos con permisos adecuados al entorno.

## Credenciales SNMPv3

- Usa un usuario dedicado `authPriv` de solo lectura y el menor alcance posible.
- No escribas frases secretas en JSON ni en argumentos de proceso.
- Facilita los secretos mediante variables `NETRA_SNMP_*` solo durante la ejecución.
- Rota o elimina el usuario cuando deje de ser necesario.

El motor implementa consultas `GET` y `GETBULK`; no implementa `SET`.

## Comunicación de vulnerabilidades

No incluyas credenciales, artefactos reales ni detalles identificativos de una red en un canal público. Antes de una distribución pública debe definirse y publicarse un canal privado de reporte del responsable del producto.
