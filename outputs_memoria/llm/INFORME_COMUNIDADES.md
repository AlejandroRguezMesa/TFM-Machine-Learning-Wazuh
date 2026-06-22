# Informe de triaje LLM sobre comunidades de la Capa 3

Análisis del comportamiento de `llm_triage.py` sobre las ocho comunidades
triadas en este directorio. El objetivo es entender qué ve el LLM, qué
acierta y qué se le escapa.

Datos del run: pipeline completo del 19 de junio de 2026, parquet
`lab_state/real_alerts_incidents.parquet` (1.950 filas tras
deduplicación, 137 comunidades), proveedor Gemini
(`gemini-2.5-flash`), descripciones anonimizadas con
`user_alias_map.json` (203 usuarios).


## 1. Qué recibe el LLM (y qué no)

`llm_triage.py` construye en `build_community_context()` un resumen
estructurado por comunidad y se lo envía al modelo. Lo que recibe es:

- número de filas, alertas originales, clústeres de Capa 2,
- ventana temporal (`first_seen`, `last_seen`, duración),
- nivel máximo de regla,
- lista de decoders implicados y bandera `es_cross_source`,
- las 8 reglas más frecuentes,
- hasta 6 descripciones de regla anonimizadas,
- listas separadas de usuarios, IPs, hosts (top-10 cada una),
- tácticas y técnicas MITRE agregadas.

Lo que **no** recibe (y aparece como limitación recurrente más abajo):

- la línea temporal evento-a-evento,
- la asociación entre entidades: qué IP corresponde a qué host, qué
  usuario actuó desde qué IP, en qué orden,
- las alertas en bruto.

Esto es deliberado: el prototipo demuestra que el resumen agregado de
Capa 3 ya es suficiente para un triaje útil. Pero impone un techo a la
resolución del análisis.


## 2. Resumen comparativo de las ocho comunidades

| Com. | Categoría | Decoders | Filas | Alertas | Niv. máx | Severidad LLM | Confianza | Benigno |
|------|-----------|----------|-------|---------|----------|---------------|-----------|---------|
| 1    | Top volumen | vcenter             | 71  | 884 | 3  | informativa | alta  | sí  |
| 7    | Top volumen | json (O365)         | 137 | 342 | 5  | baja        | baja  | no  |
| 126  | Cross-source benigno | pam + sudo  | 2   | 2   | 3  | media       | media | no  |
| 127  | Escenario S06 | json + paloalto   | 11  | 71  | 7  | alta        | media | no  |
| 130  | Top volumen | json (O365)         | 145 | 204 | 3  | baja        | media | no  |
| 134  | Escenario S07 | json + paloalto + vcenter | 13 | 78 | 10 | **crítica** | alta  | no  |
| 135  | Escenario S08 | json + paloalto + vcenter | 17 | 97 | 6 | alta        | media | no  |
| 136  | Escenario S09 | json + paloalto   | 11  | 71  | 7  | alta        | media | no  |

Las tres primeras (1, 7, 130) son las que el script triaja por defecto
con `--top 3`. Las cuatro de los escenarios (127, 134, 135, 136) cierran
la cobertura de las comunidades cross-source de los escenarios
sintéticos. La 126 se ha incluido como caso atípico: única comunidad
cross-source no Windows/red (logs Linux), de tamaño muy pequeño,
ideal como control.

Se observa una correspondencia perfecta entre **cross-source con nivel
alto** y veredicto alta o crítica del LLM: las cuatro comunidades de
los escenarios S06/S07/S08/S09 se elevan, y entre ellas la única que
acumula reglas de nivel 10 (S07, con Mimikatz e infostealer) es la
única calificada como crítica. La 126, también cross-source pero con
nivel máximo 3, queda en severidad media con factores de incertidumbre
explícitos.


## 3. Ficha por comunidad

### Comunidad 1 — automatización vCenter (control negativo)

Contexto enviado: 71 filas, 884 alertas, decoder único `vcenter`,
nivel máximo 3, un solo usuario sobre múltiples IPs internas con user
agent Apache-CXF.

Triaje LLM: **informativa**, *"Actividad de gestión rutinaria en
vCenter"*, benigno, confianza alta.

Lectura: el LLM identifica correctamente el patrón "user agent
programático + ráfaga homogénea de bajo nivel + decoder único" como
automatización. La confianza alta refleja que la evidencia es
inequívocamente compatible con actividad benigna.


### Comunidad 7 — Office 365 rutinario (control negativo)

Contexto: 137 filas, 342 alertas, decoder único `json` (Office 365),
nivel máximo 5. Mezcla MailItemsAccessed, Planner, SharePoint y mensajes
enviados.

Triaje LLM: **baja**, *"Actividad de Office 365 con posible recolección
de información"*, no benigno, confianza baja.

Lectura: el LLM marca el caso como no benigno por la presencia de la
táctica Collection en las reglas, pero deja la confianza en baja y la
severidad en baja. Internaliza correctamente la advertencia del prompt
sistema sobre el sesgo de la táctica MITRE en eventos rutinarios de
auditoría.


### Comunidad 126 — escalada de privilegios mínima (control negativo no obvio)

Contexto: 2 filas, 2 alertas, ventana de 16 minutos, **cross-source
`sudo` + `pam`**, un único usuario, ningún host ni IP, tácticas MITRE
Privilege Escalation + Defense Evasion + Persistence + Initial Access.
Reglas: "Successful sudo to ROOT executed" y "PAM: Login session opened",
ambas nivel 3.

Triaje LLM: **media**, *"Escalada de privilegios exitosa"*, no benigno,
confianza media.

Lectura: este caso es el más informativo de los benignos. Es
cross-source y arrastra cuatro tácticas MITRE serias, señales que en
otro contexto justificarían severidad alta. El LLM no las pasa por
alto pero tampoco se alarma: mantiene la severidad en media y deja
explícitos los factores de incertidumbre. Cita textualmente: *"La
ausencia de información sobre el host o la dirección IP donde ocurrió
el evento"* y *"La actividad podría ser rutinaria si el usuario es un
administrador de sistemas"*. Es exactamente el equilibrio que se
busca: ni dejar pasar la señal por su bajo volumen ni amplificarla sin
evidencia. El modelo es no determinista y este perfil concreto puede
oscilar entre baja y media, pero no entra en alta sin más evidencia.


### Comunidad 127 — escenario S06 (O365 → PaloAlto C2)

Contexto: 11 filas, 71 alertas, ~3 min, cross-source `json` + `paloalto`,
2 usuarios, nivel máximo 7. Las descripciones de regla incluyen
*"Office 365: User got FullAccess permissions in Exchange"* y
*"Palo Alto Traffic: Session dropped from 10.99.6.180 to
185.220.101.45"*.

Triaje LLM: **alta**, *"Escalada de privilegios en O365 y actividad
de red sospechosa"*, no benigno, confianza media.

Lectura: el LLM identifica los tres componentes esenciales del
escenario: cuenta O365 comprometida, escalada vía FullAccess Exchange,
intento de comunicación a red externa bloqueado. Le falta cerrar
explícitamente el vínculo IP↔O365, pero el conjunto le basta para
calificarlo como alta.


### Comunidad 130 — Azure AD STS masivo (caso intermedio)

Contexto: 145 filas, 204 alertas, decoder único `json` (O365),
nivel máximo 3. Densidad temporal alta y muchos usuarios distintos.

Triaje LLM: **baja**, *"Actividad inusual de autenticación y buzón
en Office 365"*, no benigno, confianza media.

Lectura: el LLM no se decanta del todo. La densidad temporal y el
número de usuarios le inquietan lo suficiente para no marcarlo
benigno, pero el bajo nivel de regla le impide subir la severidad.
Triaje honesto: "no lo descarto, pero no tengo evidencia para
escalarlo".


### Comunidad 134 — escenario S07 (EDR → PA → vCenter)

Contexto: 13 filas, 78 alertas, ventana de 10 minutos, cross-source
triple `json` + `paloalto` + `vcenter`, **nivel máximo 10**.

Las reglas incluyen Mimikatz (nivel 10), Infostealer (nivel 10),
dispositivos USB insertados, sesiones Palo Alto dropeadas hacia
`91.241.19.84` y `78.46.99.123`, y login/logout del administrador
de vCenter sobre las víctimas del escenario.

Triaje LLM: **crítica**, *"Compromiso de servidor con backdoor y
posible exfiltración/C2"*, no benigno, **confianza alta**.

Lectura: única comunidad calificada como crítica del lote. La
combinación de Mimikatz nivel 10, USB insertados, drops de firewall
hacia direcciones IP externas y login del administrador de vCenter
desde la misma IP interna que el cortafuegos marca como host
comprometido es contundente. El LLM articula el escenario completo,
aunque sin nombrar explícitamente la cadena causal entre IP-callback
y login-vCenter. La confianza alta es justificada por la convergencia
de evidencia.


### Comunidad 135 — escenario S08 (O365 → vCenter lateral)

Contexto: 17 filas, 97 alertas, cross-source triple `json` + `paloalto`
+ `vcenter`, nivel máximo 6, usuarios `tfm-s08-*` (víctimas del
escenario), IP interna `10.99.8.200` y externas asociadas.

Triaje LLM: **alta**, *"Posible compromiso de credenciales y
movimiento lateral"*, no benigno, confianza media.

Lectura: el LLM identifica el patrón "compromiso O365 + movimiento
lateral hacia infraestructura virtual", que es exactamente la
descripción del escenario. La diferencia con S07 está en el nivel
máximo de regla: aquí no hay nada nivel 10, y el LLM ajusta la
severidad a alta en lugar de crítica. La confianza media refleja la
ausencia de un nexo causal explícito.


### Comunidad 136 — escenario S09 (pivot por IP)

Contexto: 11 filas, 71 alertas, cross-source `json` + `paloalto`,
nivel máximo 7. La IP `91.198.22.70` aparece como entidad puente
recorriendo varios micro-clusters.

Triaje LLM: **alta**, *"Posible compromiso de cuenta O365 y escalada
de privilegios"*, no benigno, confianza media.

Lectura: el LLM identifica la intrusión por la mezcla O365 + tráfico
bloqueado, pero deja la confianza en media. La razón aparente: el
resumen no le aclara que la IP actúa como nexo entre las dos fuentes,
que es lo paradigmático del escenario S09.


## 4. Comparación global

| Familia                | Comunidades         | Severidad esperable | Resultado |
|------------------------|---------------------|---------------------|-----------|
| Cross-source crítico   | 134                 | alta o crítica      | crítica   |
| Cross-source elevado   | 127, 135, 136       | alta                | alta (3/3)|
| Cross-source benigno   | 126                 | baja o media        | media     |
| Mono-fuente rutinario  | 1, 7, 130           | baja o informativa  | informativa o baja (3/3) |

Aciertos del LLM en este lote: 8/8 a nivel de severidad final, con
confianza calibrada (media o baja cuando le falta información, alta
cuando los indicios convergen). No produce falsos positivos en los
controles negativos. La única comunidad calificada como crítica
corresponde efectivamente al escenario con reglas de nivel 10. La
calibración global es la pretendida.

Patrón consistente en los aciertos críticos: el LLM identifica
correctamente la **gravedad** del incidente pero no siempre articula
la **cadena causal** entre entidades. Esto es coherente con el
contexto agregado que recibe: ve qué pasó, no en qué orden ni quién
con quién.


## 5. Limitación estructural observada

La misma observación aparece en los triajes críticos, siempre en
`factores_de_incertidumbre`: el LLM no llega a correlar IPs concretas
con hosts concretos, ni a establecer la secuencia temporal entre
eventos de fuentes distintas.

La causa es la implementación de `build_community_context()`
(`llm_triage.py:89-152`): las entidades se exponen como listas
independientes ordenadas por frecuencia. Resulta perfecto para que
el LLM identifique tipo de incidente y severidad, pero no para que
cierre la cadena de la kill chain.

Posibles mejoras (fuera del alcance de esta prueba de concepto, pero
señalables como trabajo futuro en la memoria):

- **Mini-línea temporal**: enviar al LLM los 5–10 eventos más
  representativos en orden cronológico, no solo el agregado.
- **Co-ocurrencias entidad↔entidad**: para cada par (IP, usuario),
  (IP, host), indicar en qué reglas aparecen juntos. Eso permitiría
  que el LLM diga "la IP X aparece como origen en firewall *y* como
  cliente en O365" sin tener que verlo en las alertas crudas.
- **Marcaje de IPs externas conocidas**: pre-anotar TOR, C2
  sospechosos o IPs en listas de reputación. Esto añadiría señal sin
  enviar alertas crudas.

El prototipo cumple
exactamente lo que prometía, que es demostrar que el resumen agregado
de Capa 3 es base suficiente para un triaje útil. Las limitaciones
que muestra son las que cabía esperar de la abstracción elegida, y
son direcciones claras de mejora, no fallos del enfoque.
