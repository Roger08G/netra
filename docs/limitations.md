# Límites conocidos

- Un portátil conectado a un puerto normal de un switch no ve automáticamente todo el tráfico de la red.
- Una caché ARP es una observación local y temporal, no un inventario completo.
- No responder a ICMP no demuestra que un dispositivo esté apagado.
- Una conexión TCP aceptada demuestra accesibilidad desde el punto de observación, no una vulnerabilidad.
- Una MAC aprendida por un puerto no prueba una conexión física directa.
- LLDP importado es una declaración observada. Netra mantiene el enlace físico como inferido hasta disponer de evidencia adicional.
- Esta entrega no barre IPv6. Solo define el límite arquitectónico; no intenta enumerar un `/64`.
- SNMPv3 usa MIB estándar, pero todavía no se ha validado contra modelos reales de distintos fabricantes. Una tabla no implementada aparece en `coverage.issues`.
- No hay API de fabricante, captura LLDP, descubrimiento IPv6 activo ni auditoría de vulnerabilidades en vivo.
- El informe no afirma que la red sea segura ni que haya sido analizada al 100 %.
- La comprobación de servicios no lee banners, no autentica y no explota.
- La identidad entre ejecuciones usa el identificador normalizado del activo. Si una observación basada solo en IP pasa a identificarse por MAC, `netra diff` puede mostrar retirada y alta en lugar de una continuidad no demostrada.
- La distribución binaria 1.0.0 está preparada para Windows de 64 bits. Otros sistemas pueden ejecutar desde fuentes, pero no forman parte del paquete de producción validado.

El modo pasivo significa "sin sondas activas emitidas por Netra"; la lectura de la caché local puede contener información generada previamente por el sistema operativo.
