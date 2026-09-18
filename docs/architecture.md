# Arquitectura 1.0

## Límite de autoridad

La CLI Python se ocupa de comandos, confirmación del usuario y presentación. El motor Go decide si un alcance es válido, ejecuta los recolectores, correlaciona observaciones y escribe el artefacto de la ejecución.

```text
CLI Python
  │ orden JSON por stdin
  ▼
Motor Go ─── policy ─── collectors
  │                 │
  │                 └─ local / neighbor cache / ICMP / TCP
  ├─ correlation ── FDB + LLDP importados
  ├─ artifact JSON (escritor único)
  └─ eventos NDJSON por stdout
```

`stderr` queda reservado para diagnósticos. Los mensajes tienen versión de protocolo, identificador de petición, tipo, fecha y carga estructurada.

La CLI valida que cada evento pertenezca a la petición y versión esperadas. El motor rechaza campos desconocidos para evitar configuraciones aparentemente aceptadas pero ignoradas. Al cancelar, la CLI señaliza el proceso y aplica terminación forzada solo si no responde; el artefacto final se publica mediante reemplazo transaccional.

## Modelo de certeza

Los estados tienen semántica cualitativa:

- `observed`: la fuente comunicó directamente el dato descrito;
- `inferred`: una regla documentada deriva la relación de una o más observaciones;
- `unknown`: falta evidencia para resolver la relación;
- `contradictory`: fuentes vigentes sostienen conclusiones incompatibles.

No se asignan porcentajes de confianza no calibrados.

Una entrada FDB produce `mac_learned_on_port`. Esta relación significa que el switch aprendió la MAC a través de un puerto. Solo una MAC en un puerto sin un bridge anunciado por LLDP permite añadir `physical_attachment`, y aun así su estado es `inferred`.

## Evidencia gestionada

Netra admite dos fuentes que terminan en el mismo modelo normalizado: un snapshot JSON y consultas SNMPv3 `authPriv`. El correlador no depende de la procedencia y conserva `snmpv3:fdb` o `snmpv3:lldp` en la evidencia.

El recolector SNMPv3 consulta identidad, nombres de interfaz, correspondencia entre bridge ports e `ifIndex`, tablas FDB, asociación Q-BRIDGE entre FDB y VLAN y vecinos LLDP. El motor solo expone operaciones `GET` y `GETBULK`; no llama a `SET`.

Los destinos son direcciones IPv4 literales que el motor vuelve a comprobar contra el plan. La configuración contiene referencias `NETRA_SNMP_*`; la CLI resuelve sus valores, elimina esas variables del entorno hijo y transmite las frases por `stdin`. Los eventos y el artefacto no incluyen la configuración ni las credenciales.

Un error en una tabla opcional no invalida toda la auditoría: se registra en `coverage.issues`. Una configuración inválida o fuera de alcance sí detiene la ejecución antes de abrir una sesión.

## Persistencia

El motor escribe un artefacto JSON versionado mediante un archivo temporal y un cambio de nombre. El informe HTML consume ese artefacto; no reinterpreta protocolos ni genera nuevas conclusiones.

`netra diff` compara vistas estables de activos, servicios y relaciones. Omite marcas temporales y evidencia repetida para no presentar una nueva observación del mismo estado como un cambio de red.

## Distribución

La distribución 1.0.0 es un wheel nativo de Windows 64 bits. Contiene la CLI Python y `netra-engine.exe`, se marca como no-puro y usa una etiqueta de plataforma Windows. El proceso de build inspecciona el wheel y realiza una instalación limpia antes de producir el checksum SHA-256.
