<h1 align="center">ReqEye</h1>
<p align="center">
  🇺🇸 <a href="README.md"><b>English</b></a> |
  🇪🇸 <b>Español</b>
</p>
<p align="center">
  <img width="395" height="137" alt="image" src="https://github.com/user-attachments/assets/5d01f6ab-d229-4ca1-894e-d99b6059cfad" />
</p>
<h2 align="center">
ReqEye es un asistente CLI para el análisis de requests HTTP, diseñado para ayudar a investigadores de seguridad, bug bounty hunters y pentesters a identificar puntos de entrada de alto valor que merecen pruebas manuales.

No escanea objetivos, no envía tráfico ni afirma la existencia de vulnerabilidades.
ReqEye se enfoca en **dónde mirar**, no en hacer suposiciones.

</h2>

## Filosofía

> ReqEye no encuentra bugs.
> Encuentra **lugares donde es probable que existan bugs**.

Las vulnerabilidades web modernas — especialmente IDOR, bypass de autenticación y fallas de lógica — son altamente **dependientes del contexto**. Los escáneres totalmente automatizados fallan en este punto.

ReqEye actúa como un **asistente de razonamiento**:

* Analiza requests HTTP crudos
* Detecta patrones relevantes para seguridad
* Resalta **superficies de ataque y puntos de entrada**
* Sugiere **pruebas manuales** que un humano debería intentar

Sin ruido. Sin escaneo ciego. Sin falsa autoridad.

---

## Características clave

* Parseo de requests HTTP crudos (estilo Burp / DevTools)
* Clasificación de endpoints por **riesgo y propósito**
* Identificación de **puntos de entrada de alto valor** (IDOR, auth, roles, cambios de estado)
* Detección de **indicadores relevantes de seguridad** sin sobreafirmar
* Generación de **requests mutados offline** para pruebas manuales
* Comparación de respuestas HTTP para detectar cambios de comportamiento
* Reportes limpios y amigables para la terminal

---

## Lo que ReqEye NO es

* ❌ No es un escáner automático de vulnerabilidades
* ❌ No es un fuzzer que envía tráfico
* ❌ No reemplaza a Burp, al análisis manual ni al uso del cerebro

ReqEye está pensado para usarse **antes o durante las pruebas manuales**, para priorizar el esfuerzo.

---

## Instalación

ReqEye está escrito en **Python puro**.

```bash
git clone https://github.com/urdev4ever/reqeye.git
cd reqeye
python reqeye.py
```

### Dependencia opcional

En sistemas Windows, ReqEye usará **opcionalmente** `colorama` para un soporte correcto de colores ANSI.

Si `colorama` no está instalado, los colores se desactivan automáticamente.

```bash
pip install colorama
```

Esta dependencia es **opcional**.

---

## Uso

```bash
python reqeye.py --help
```

<img width="500" height="509" alt="image" src="https://github.com/user-attachments/assets/cac15c51-953b-40be-be13-7b2acdac495d" />

---

### Parsear un request

```bash
python reqeye.py parse request.txt
```

Parsea y muestra:

* Método
* Ruta
* Headers
* Parámetros de query
* Parámetros del body

---

### Analizar un endpoint

```bash
python reqeye.py analyze request.txt
```

Salida:

* Clasificación del endpoint

* Puntuación de riesgo

  <img width="434" height="93" alt="image" src="https://github.com/user-attachments/assets/25a401bb-ce4d-45be-88a1-388f3f8a0631" />

* Puntos de entrada identificados

  <img width="371" height="125" alt="image" src="https://github.com/user-attachments/assets/5b24dd68-a515-499a-9928-ef6afd41c586" />

* Indicadores de seguridad

  <img width="622" height="363" alt="image" src="https://github.com/user-attachments/assets/a28b96bd-d708-4e7a-aaf5-8e6d20cb2e01" />

* Recomendaciones para pruebas manuales

  <img width="354" height="161" alt="image" src="https://github.com/user-attachments/assets/a0bcab52-2715-4f1b-a1ff-f20209dc299e" />

> Los siguientes resultados provienen de un request autorizado (gracias Mercado Libre)

---

### Generar requests mutados (offline)

```bash
python reqeye.py mutate request.txt
```

Crea versiones modificadas del request para:

* Pruebas de IDOR
* Intentos de bypass de autenticación
* Manipulación de roles / privilegios
* Pruebas de estado y lógica

Estos requests **no se envían** — están pensados para copiarse en Burp u otras herramientas similares.

---

### Comparar respuestas

```bash
python reqeye.py diff response1.txt response2.txt
```

Resalta:

* Cambios en el código de estado
* Diferencias significativas de longitud
* Cambios estructurales

Útil para detectar cambios de comportamiento tras manipulaciones manuales.

---

### Generar un reporte

```bash
python reqeye.py report request.txt
```

Genera un reporte conciso que incluye:

* Resumen del endpoint
* Puntos de entrada encontrados
* Evaluación de riesgo
* Checklist de pruebas

---

## Puntuación de riesgo

ReqEye asigna una **puntuación heurística de riesgo (0–100)** basada en:

* Sensibilidad del endpoint
* Presencia de puntos de entrada
* Contexto de autorización
* Indicadores de control de parámetros

La puntuación está pensada para **priorización**, no como prueba.

---

## Filosofía de salida

ReqEye evita intencionalmente afirmaciones como:

* “Este endpoint es vulnerable”
* “Se encontró una falla crítica”

En su lugar, utiliza expresiones como:

* “Punto de entrada de alto riesgo”
* “Se recomienda verificación manual”
* “Indicador relevante de seguridad”

Esto lo hace seguro y adecuado para **flujos de trabajo de bug bounty**.
(Sin relleno, sin humo)

---

## Flujo de trabajo típico

1. Capturar un request (Burp / DevTools)
2. Ejecutar `reqeye analyze`
3. Revisar puntos de entrada y recomendaciones
4. Usar `reqeye mutate` para variantes de prueba
5. Probar manualmente con Burp u otras herramientas
6. Comparar respuestas si es necesario

---

## Casos de uso

* Bug bounty hunting
* Pentesting web manual
* Revisiones de seguridad en APIs
* Aprendizaje de lógica de vulnerabilidades web

---

## Descargo de responsabilidad

ReqEye es una **herramienta de asistencia para investigación**.

Eres responsable de:

* Mantenerte dentro del scope
* Seguir las reglas del programa
* Validar todos los hallazgos manualmente

---

## Contribuir

Las pull requests son bienvenidas si:

* Mejoran la precisión del parsing HTTP, la lógica de detección de entry points o el sistema heurístico de riesgo
* Mejoran la claridad de los reportes, la precisión del diff o la calidad de las mutaciones sin agregar comportamiento de escaneo automático
* Preservan la filosofía centrada en el análisis humano (sin generación de tráfico, sin afirmar explotación, sin presentar indicadores como “vulnerabilidades”)

---

Esta herramienta existe para ayudar a los humanos a enfocarse donde realmente importa.

## Nota final

ReqEye está construido sobre una idea simple:

> **Los buenos bugs los encuentran los humanos — no los escáneres.**

---

Hecho con <3 por URDev
