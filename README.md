# Laboratorio de comportamiento de ransomware

Detector **defensivo** y explicable de ransomware construido sobre tres estructuras de datos
escritas a mano: un **árbol de decisión binario** (CART), un **árbol n-ario de procesos** y un
**montículo máximo** (cola de triaje). La interfaz es una aplicación Streamlit que cambia entre
inglés y español en caliente.

> El proyecto detecta comportamiento; no lo produce. No contiene malware. Los datos de
> entrenamiento son **sintéticos por defecto**: sirven para demostrar el método, no para afirmar
> una tasa de detección real.

## Cómo iniciar la app

```bash
cd trees
pip install -r requirements.txt
streamlit run app.py
```

Se abre en `http://localhost:8501`. Para detenerla, `Ctrl+C` en la terminal. Las pruebas se
ejecutan con `python -m pytest`.

Si prefieres aislar las dependencias, crea antes un entorno virtual con
`python -m venv .venv` y actívalo (`.venv\Scripts\activate` en Windows,
`source .venv/bin/activate` en Linux o macOS).

## Uso

En la aplicación:

1. **Barra lateral** — idioma (English / Español), origen de los datos, criterio de impureza,
   profundidad máxima, muestras mínimas por hoja y umbral de riesgo. El umbral se aplica al
   instante; los demás cambios requieren **Reentrenar modelo**.
2. **Pestaña Detección** — crea procesos con cualquier perfil, selecciónalos en el árbol y mira el
   veredicto, las razones y el laboratorio de evasión.
3. **Pestaña Modelo** — el árbol de decisión dibujado, con el camino del proceso seleccionado
   resaltado, y la importancia de cada característica.
4. **Pestaña Incidente** — la cola de triaje ordenada por riesgo.

Para entrenar con datos propios, activa **Subir CSV** en la barra lateral. Una fila por proceso,
con las cinco columnas de arriba más `label` (0 = benigno, 1 = ransomware), y ambas clases
presentes:

```csv
files_per_sec,entropy,rename_ratio,shadow_delete,dirs_touched,label
80.5,7.9,0.91,1,92,1
0.7,5.1,0.00,0,3,0
```

## El caso de estudio

Un antivirus por firmas no reconoce una familia de ransomware que nunca ha visto. El
comportamiento, en cambio, se repite: cifrar rápido, escribir contenido de alta entropía, renombrar
en masa, borrar las copias de seguridad y recorrer muchos directorios. El caso de estudio consiste
en detectar ransomware a partir de ese comportamiento, con cinco características numéricas por
proceso:

| Columna | Significado | Rango |
|---|---|---|
| `files_per_sec` | Archivos escritos por segundo | 0–400 |
| `entropy` | Entropía de Shannon del contenido escrito, en bits por byte | 0–8 |
| `rename_ratio` | Proporción de escrituras seguidas de un renombrado | 0–1 |
| `shadow_delete` | Se observó borrado de copias de seguridad | 0 o 1 |
| `dirs_touched` | Directorios distintos en los que escribió | 0–400 |

El laboratorio hace cinco cosas con ellas:

1. **Entrena un árbol de decisión** a partir de observaciones etiquetadas.
2. **Clasifica un proceso y se explica**: cada veredicto muestra las reglas exactas que se
   evaluaron, la lectura observada en cada una y cuántas muestras de entrenamiento respaldan la
   hoja a la que llegó.
3. **Reconstruye la cadena del ataque**: un proceso detectado marca a sus ancestros como
   sospechosos, porque el padre que lanzó el cifrador es parte del incidente.
4. **Prioriza el incidente**: los procesos detectados entran en un montículo máximo, así el
   analista siempre ve primero el de mayor riesgo.
5. **Muestra dónde se rompe el modelo**: el laboratorio de evasión permite bajar la velocidad o la
   entropía de un cifrador y ver el veredicto cambiar a benigno. Un falso negativo es un equipo
   cifrado, así que este es el panel más honesto de la aplicación.

Los perfiles sintéticos incluyen dos benignos incómodos a propósito: un **agente de copias de
seguridad** (escribe rápido en muchos directorios) y un **compresor de archivos** (produce alta
entropía y renombra lo que reemplaza). Existen para que ninguna característica por sí sola separe
las clases y el árbol tenga que combinarlas.

---

# Las estructuras de datos

## 1. Árbol de decisión binario (CART) — `ransomware_lab/decision_tree.py`

Es el clasificador: decide si un proceso es ransomware y, sobre todo, explica por qué.

### Representación

Un **grafo recursivo de objetos**, no un arreglo: cada nodo es dueño de sus subárboles, así que
cualquier nodo es un árbol válido por sí mismo y la estructura no necesita aritmética de índices.

```
ClassificationNode (abstracta)
├── BehaviorSplit   → regla + on_match + on_violation   (nodo interno, siempre 2 hijos)
└── VerdictLeaf     → distribución de clases            (nodo terminal)
```

Ambos tipos implementan las mismas cuatro operaciones — `resolve`, `accept`, `walk`, `height` —, de
modo que todo recorrido es polimórfico y no hay un solo `isinstance` en el camino caliente. Un nodo
guarda únicamente lo que aprendió durante el entrenamiento (`sample_count`, `ransomware_ratio`),
nunca una referencia a las filas, así un árbol entrenado es pequeño e independiente del conjunto de
datos.

`DecisionRule` es un par inmutable `(característica, umbral)` con la comparación incorporada
(`lectura <= umbral` va a la izquierda). Tener la comparación dentro de la regla es lo que permite
que la interfaz imprima una razón legible sin volver a deducir la dirección de la prueba.

### Cómo se construye

`CartTreeBuilder._grow` es el procedimiento CART recursivo:

1. Detenerse y emitir una `VerdictLeaf` si el nodo es puro, está demasiado profundo o tiene
   demasiado pocas muestras (`GrowthLimits`).
2. Si no, buscar la partición que maximiza la reducción de impureza
   `ΔI = I(padre) − (n_izq/n)·I(izq) − (n_der/n)·I(der)`.
3. Partir las observaciones una sola vez con la regla ganadora y recurrir sobre ambas mitades.

La búsqueda de la partición es la parte que merece leerse. La versión ingenua prueba cada umbral
candidato volviendo a partir el conjunto, lo que cuesta `O(m · n²)` por nodo y deja la interfaz
inservible. En su lugar, `_sweep` ordena las observaciones **una vez por característica** y las
recorre manteniendo contadores acumulados del lado izquierdo:

```
ordenado por característica →  o₁  o₂  o₃  o₄  o₅  o₆ ...
                                   ↑ umbral candidato = punto medio(o₂, o₃)
izquierda = (tamaño, maliciosos)       se actualiza en O(1) por paso
derecha   = (total − tamaño, maliciosos_total − maliciosos)
```

Como Gini y entropía dependen solo de `(tamaño, maliciosos)`, cada candidato se evalúa en `O(1)` y
el nodo completo cuesta `O(m · n log n)`, dominado por el ordenamiento. Los umbrales se colocan en
el punto medio entre valores distintos consecutivos, y los candidatos que dejarían una hoja por
debajo de `min_samples_leaf` o que ganan menos de `min_impurity_decrease` se descartan durante el
mismo barrido.

El criterio de impureza es una estrategia intercambiable (`GiniImpurity`,
`ShannonEntropyImpurity`) que expone `score(total, maliciosos)`. Esa firma —contadores en vez de un
conjunto de datos— es justamente lo que permitió el barrido sin casos especiales.

| Operación | Costo | Dónde |
|---|---|---|
| Entrenar | `O(m · n log n)` por nodo | `CartTreeBuilder._grow` |
| Clasificar un proceso | `O(h)`, h = altura | `BehaviorSplit.resolve` |
| Trazar la explicación | `O(h)` | `BehaviorDecisionTree.trace` |
| Altura / hojas / recorrido | `O(k)`, k = nodos | `ClassificationNode.walk` |
| Importancia de características | `O(k)` | `_ImpurityImportance` (Visitor) |

### Cómo se aplica en la interfaz

`trace` devuelve un `DecisionPath` con las `RuleOutcome` en orden, la hoja alcanzada y los nodos
visitados. La pestaña **Detección** usa las reglas para la lista de razones; la pestaña **Modelo**
usa los nodos visitados para resaltar el camino dentro del diagrama. El camino lleva **datos
estructurados, no frases ya formateadas**, que es lo que hace la explicación traducible.

## 2. Árbol n-ario de procesos — `ransomware_lab/process_tree.py`

Es la cadena del ataque: quién lanzó a quién.

### Representación

Un `MonitoredProcess` es un nodo Composite con un puntero al padre y una lista ordenada de hijos,
de modo que la estructura es un árbol de aridad arbitraria que refleja cómo el sistema operativo
reporta el linaje:

```
System (4)
├── winword.exe (1004)
│   └── updater.exe (1006)        ← detectado: cifrador sigiloso
└── backup-agent.exe (1005)
```

`ProcessTree` envuelve la raíz y añade un **índice hash** (`dict[int, MonitoredProcess]`) para
resolver un pid en `O(1)` en vez de recorrer el árbol en cada recarga de la interfaz. El índice y
la estructura se actualizan en el mismo método, y por eso `attach` es la única forma pública de
agregar un proceso.

### Recorridos

Tres recorridos, cada uno escrito para la pregunta que responde:

- `breadth_first` — por niveles, con un `collections.deque` como cola FIFO; `popleft` es `O(1)`,
  mientras que una lista pagaría `O(n)` por desplazamiento. Es el orden de iteración por defecto
  del árbol porque también es el orden en que la interfaz lista los procesos.
- `depth_first` — iterativo con pila explícita (los hijos se apilan invertidos para conservar el
  orden izquierda-derecha). Iterativo y no recursivo para que un linaje profundo no desborde la
  pila de Python.
- `ancestors` — sube por los punteros al padre en `O(d)`; es lo que convierte una sola detección en
  la cadena de sospechosos que se pinta en el diagrama.

### Invariantes

Un árbol que acepta un ciclo en silencio deja de ser un árbol, así que los métodos que mutan
validan primero y lanzan `ProcessLineageError`: pid duplicado, padre desconocido, reasignar un
proceso que ya tiene padre, y colgar un ancestro debajo de su propio descendiente (el caso del
ciclo, comprobado contra el recorrido de ancestros).

| Operación | Costo |
|---|---|
| `attach` / `find` / `require` | `O(1)` amortizado (+ `O(d)` de verificación de ciclo) |
| `breadth_first` / `depth_first` | `O(n)` |
| `ancestors` / `lineage_of` | `O(d)` |
| `height` | `O(n)` |

## 3. Montículo máximo binario — `ransomware_lab/triage.py`

Es la cola de triaje: qué proceso atiende primero el analista.

### Representación

`ThreatTriageQueue` es un **árbol binario completo aplanado en una lista** de Python, escrito con
aritmética de índices explícita en vez de delegar en `heapq`, porque aquí el montículo es el tema:

```
índice:   0      1      2      3      4      5
        0.98   0.91   0.74   0.55   0.60   0.41
padre(i) = (i−1)//2      hijos(i) = 2i+1, 2i+2
```

La propiedad de montículo es `padre.prioridad >= hijo.prioridad` para todo nodo, así que
`_tickets[0]` siempre es la alerta de mayor riesgo. `_sift_up` la restaura tras un `append` y
`_sift_down` después de que la raíz es reemplazada por el último elemento: el par estándar de
reparaciones en `O(log n)`.

### El orden

Un montículo vale lo que valga su comparación. `TriageTicket.priority` devuelve
`(riesgo, -llegada)`: decide el riesgo y, en caso de empate, gana el ticket que llegó primero, de
modo que las alertas con el mismo riesgo conservan el orden FIFO en vez de uno arbitrario. El campo
`arrival` queda fuera de la igualdad (`compare=False`), así dos tickets de la misma alerta siguen
siendo iguales.

`holds_heap_invariant()` comprueba la propiedad en todo el arreglo; las pruebas la llaman después
de cada inserción y extracción de 400 tickets aleatorios, que es como se verifica la lógica de
flotación y hundimiento en vez de darla por buena.

| Operación | Costo |
|---|---|
| `admit` (insertar) | `O(log n)` |
| `pop` | `O(log n)` |
| `peek` | `O(1)` |
| `most_critical(k)` | `O(n + k log n)`, no destructivo (trabaja sobre una copia) |
| `drain` | `O(n log n)`, entrega el riesgo en orden no creciente |

## 4. Estructuras de apoyo

| Estructura | Dónde | Por qué es la adecuada |
|---|---|---|
| Vector inmutable de tuplas | `BehaviorVector` | Vector de características de ancho fijo con acceso `O(1)`; `with_reading` devuelve un vector nuevo, así una observación nunca se muta a espaldas del detector |
| Secuencia de solo lectura | `TelemetryDataset` | Envuelve una tupla de observaciones y responde `class_counts`, `malicious_count`, `is_pure` y `subset` sin copiar filas en cada consulta |
| Índice hash | `ProcessTree._by_pid` | Búsqueda de pid en `O(1)` para una interfaz que resuelve pids en cada recarga |
| Cola FIFO (`deque`) | `MonitoredProcess.breadth_first` | Desencolado en `O(1)` para el recorrido por niveles |
| Pila explícita | `MonitoredProcess.depth_first` | Recorrido en profundidad sin recursión |
| Cubetas estratificadas | `StratifiedFoldSplitter` | Reparto round-robin de los índices por clase, así cada pliegue conserva la proporción original |

---

# Estructura del proyecto

```
trees/
├── app.py                        punto de entrada: tres líneas, llama a render_page()
├── .streamlit/config.toml        tema oscuro, color de acento
├── ransomware_lab/
│   ├── telemetry.py              BehaviorFeature, BehaviorVector, TelemetryDataset
│   ├── profiles.py               perfiles de comportamiento y distribuciones por característica
│   ├── sources.py                SyntheticTelemetrySource, CsvTelemetrySource
│   ├── decision_tree.py          CART: nodos, criterios, constructor, camino de explicación
│   ├── process_tree.py           MonitoredProcess, ProcessTree
│   ├── triage.py                 ThreatTriageQueue (montículo máximo binario)
│   ├── evaluation.py             ConfusionMatrix, StratifiedFoldSplitter, informes
│   ├── detector.py               fachada RansomwareDetector, ThreatAssessment
│   ├── session.py                LabSession, el estado de la aplicación
│   ├── diagrams.py               DOT de Graphviz para ambos árboles
│   ├── i18n.py                   Translator, tablas de frases en inglés y español
│   └── ui/
│       ├── page.py               composición: barra lateral, encabezado y tres pestañas
│       ├── theme.py              configuración de página y hoja de estilos
│       ├── state.py              acceso a st.session_state (laboratorio, idioma, reinicio)
│       ├── sidebar.py            origen de datos, controles del modelo, umbral de riesgo
│       ├── formatting.py         ayudantes de presentación (insignias, medidores, reglas)
│       └── panels/               un módulo por panel: header · processes · assessment ·
│                                 evasion · decision_tree · triage · importance
└── tests/                        58 pruebas, incluidas ejecuciones de la app sin navegador
```

Cada panel expone una sola función `render(session, translate)`: sabe dibujarse y nada más.
`page.py` es el único archivo que decide la disposición y `state.py` el único que toca
`st.session_state`. Ningún panel construye objetos del dominio ni produce texto del dominio: el
detector devuelve datos y la interfaz los formatea, que es lo que permite traducir la aplicación
entera —diagramas incluidos— sin tocar la lógica.
