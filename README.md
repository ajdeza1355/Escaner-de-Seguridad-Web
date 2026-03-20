# Escáner de Seguridad Web - Evaluador de Postura de Seguridad

## 📋 Descripción General

Este proyecto es un **escáner de seguridad web post-despliegue** que evalúa la postura de seguridad de un sitio web mediante el análisis de:
- **Certificados SSL/TLS** - Versión, validez y fecha de vencimiento
- **Cabeceras HTTP de seguridad** - Recomendadas, contextuales y obsoletas
- **Configuración de cookies** - Atributos de seguridad
- **Información general de la web** - Tecnologías expuestas

El resultado se presenta en un **informe PDF detallado** con gráficas visuales de los resultados.

---

## 🎯 Características Principales

### ✅ Análisis de Seguridad
- **Certificados SSL/TLS**: Verificación de versión (TLSv1.2 o superior) y tiempo de vencimiento
- **Cabeceras Recomendadas**: X-Frame-Options, Referrer-Policy, CSP, HSTS, CORS, etc.
- **Cabeceras Contextuales**: Detección de información sensible expuesta (X-Powered-By, Server, etc.)
- **Cabeceras Obsoletas**: Identificación de tecnologías antiguas
- **Atributos de Cookies**: Verificación de Secure, HttpOnly y SameSite

### 📊 Reportes
- Gráficos de torta con resumen general
- Gráficos de barras por categoría
- Tablas detalladas con estado de cada evaluación
- Generación automática de PDF con toda la información

### ⚙️ Configuración Personalizable
- Parámetros de conexión (timeout, puerto)
- Umbrales de validez de certificados
- Valores esperados para cabeceras de seguridad
- Directivas personalizadas de CSP y Permissions-Policy

---

## 📦 Dependencias

```txt
socket
ssl
requests
matplotlib
fpdf
tldextract
validators
logging
tempfile
os
urllib3
```

### Instalación de dependencias externas:
```bash
pip install requests matplotlib fpdf tldextract validators urllib3
```

---

## 🚀 Uso

### Ejecución básica:
```bash
python escaner_post_seguridad_web.py
```

### Flujo de ejecución:
1. **Solicita la URL** completa (ej: https://example.com)
2. **Configura parámetros** (puede usar valores por defecto presionando Enter)
3. **Realiza evaluaciones**:
   - Extrae certificado SSL/TLS
   - Obtiene cabeceras HTTP y cookies
   - Verifica configuraciones de seguridad
4. **Genera informe PDF** con nombre: `{dominio}.pdf`

---

## 📚 Funciones Principales

### 1. `validador_url(url)`
Valida y transforma la URL en formatos compatibles con socket/ssl y requests.

**Parámetros:**
- `url` (str): URL completa a validar

**Retorna:**
- Lista con [url_certificado, url_original]

---

### 2. `extractor_certificado(url_certificado, puerto, timeout)`
Extrae información del certificado SSL/TLS de la web.

**Retorna:**
- Diccionario con:
  - `Dias de validez`: Duración total del certificado
  - `Fecha vencimiento`: Días restantes para vencimiento
  - `Version SSL/TLS`: Versión de TLS utilizada
  - `Web evaluada`: URL evaluada

---

### 3. `extractor_cabeceras(url_original)`
Obtiene cabeceras HTTP y cookies de la web.

**Características:**
- Reintentos automáticos para conexiones fallidas
- User-Agent realista
- Manejo de errores de conexión

**Retorna:**
- Lista con [headers_dict, cookies_jar]

---

### 4. `verificador_cabeceras_recomendadas(...)`
Verifica la presencia y configuración correcta de cabeceras de seguridad recomendadas.

**Cabeceras verificadas:**
- X-Frame-Options
- Referrer-Policy
- X-Content-Type-Options
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- Access-Control-Allow-Origin
- Cross-Origin-Opener-Policy (COOP)
- Cross-Origin-Embedder-Policy (COEP)
- Cross-Origin-Resource-Policy (CORP)
- Permissions-Policy

**Retorna:**
- Lista con [diccionario_evaluaciones, contador_correctas, contador_incorrectas]

---

### 5. `verificador_cabeceras_contextuales(inf_headers)`
Detecta cabeceras que exponen información sensible (deben estar ausentes).

**Cabeceras verificadas:**
- X-Powered-By
- X-AspNet-Version
- X-AspNetMVC-Version
- Server

---

### 6. `verificador_cabeceras_obsoletas(inf_headers)`
Identifica cabeceras obsoletas que aún pueden estar presentes.

**Cabeceras verificadas:**
- X-XSS-Protection
- Expect-CT
- Feature-Policy
- Pragma
- Public-Key-Pins

---

### 7. `verificador_certificados(inf_certificado, conf_tiempo_vencimiento_minimo)`
Verifica la seguridad del certificado SSL/TLS.

**Criterios:**
- Versión TLS: 1.2 o superior ✓
- Vencimiento: Mínimo 30 días (configurable) ✓
- Duración total: Máximo 90 días (compatibilidad futura)

---

### 8. `verificar_cookies(inf_cookies)`
Evalúa los atributos de seguridad de las cookies.

**Atributos verificados:**
- Secure (transmisión HTTPS)
- HttpOnly (no accesible por JavaScript)
- SameSite (protección CSRF)

---

### 9. `creador_informe_pdf(...)`
Genera un informe PDF completo con los resultados.

**Contenido del PDF:**
- Portada con resumen general
- Gráfico de torta (correctas/incorrectas)
- Gráficos de barras por categoría
- Tablas detalladas con estado de cada evaluación
- Numeración de páginas

---

### 10. `conf_parametros_seguridad_web()`
Configura interactivamente los parámetros de evaluación.

**Parámetros solicitados:**
- URL a evaluar
- Timeout de conexión (default: 10 segundos)
- Puerto (default: 443)
- Tiempo mínimo de vencimiento del certificado (default: 30 días)
- Valores esperados para cabeceras personalizadas

---

### 11. `evaluador_seguridad_web()`
Función principal que orquesta todo el proceso de evaluación.

**Flujo:**
1. Solicita configuración
2. Valida URL
3. Extrae datos de la web
4. Ejecuta verificaciones
5. Genera informe PDF

---

## 📊 Ejemplo de Salida

```
Parámetros configurados:
url: https://example.com
timeout: 10
puerto: 443
tiempo_vencimiento_minimo: 30
...

Evaluación de Security Headers recomendados:
Recomendados x-frame-options ---> True
Recomendados referrer-policy ---> False
...

Evaluación de Security Headers contextuales:
contextuales x-powered-by ---> True
contextuales server ---> False
...

Conteo de configuraciones:
Correctos ---> 18
Incorrectos---> 12

Informe generado: example_com.pdf
```

---

## 🔒 Estándares de Seguridad

El escáner se basa en:
- **OWASP Secure Headers Project** - Recomendaciones de cabeceras
- **RFC 6797** (HSTS)
- **RFC 6454** (CORS)
- **MDN Web Docs** - Directivas de seguridad

### Configuraciones por defecto recomendadas:

**Content-Security-Policy:**
```
default-src 'self'; form-action 'self'; base-uri 'self'; 
object-src 'none'; frame-ancestors 'none'; 
upgrade-insecure-requests
```

**Permissions-Policy:**
```
accelerometer=(), autoplay=(), camera=(), 
cross-origin-isolated=(), display-capture=(), 
encrypted-media=(), fullscreen=(), geolocation=(), 
gyroscope=(), keyboard-map=(), magnetometer=(), 
microphone=(), midi=(), payment=(), 
picture-in-picture=(), publickey-credentials-get=(), 
screen-wake-lock=(), sync-xhr=(), usb=(), 
web-share=(), xr-spatial-tracking=()
```

---

## ⚠️ Manejo de Errores

El programa incluye manejo robusto de errores para:
- URLs inválidas
- Certificados SSL/TLS vencidos o inválidos
- Timeouts de conexión
- Errores HTTP (4xx, 5xx)
- Errores de red

Todos los errores se registran en el logger del sistema.

---

## 📝 Notas Importantes

1. **Permiso de prueba**: Asegúrese de tener permiso para evaluar la URL
2. **Fuente personalizada**: El PDF usa la fuente DejaVuSans.ttf para caracteres especiales (✔ y ⚠)
3. **Carpeta temporal**: Los gráficos se almacenan en carpeta temporal y se limpian automáticamente
4. **Requiere HTTPS**: El análisis funciona mejor con sitios HTTPS (incluye certificados)

---

## 🛠️ Estructura del Código

```
escaner_post_seguridad_web.py
├── Funciones de extracción de datos
│   ├── validador_url()
│   ├── extractor_certificado()
│   └── extractor_cabeceras()
├── Funciones de verificación
│   ├── verificador_cabeceras_recomendadas()
│   ├── verificador_cabeceras_contextuales()
│   ├── verificador_cabeceras_obsoletas()
│   ├── verificador_certificados()
│   └── verificar_cookies()
├── Funciones de visualización
│   ├── creador_gráfico_torta()
│   ├── creador_grafico_barras()
│   └── creador_informe_pdf()
├── Funciones de configuración
│   ├── conf_parametros_seguridad_web()
│   └── evaluador_seguridad_web()
└── Punto de entrada
    └── __main__
```

---

## 📄 Ejemplo de Informe PDF

El informe generado incluye:

1. **Portada** - URL evaluada y resumen general
2. **Página 1** - Gráfico de torta con porcentaje de éxito
3. **Páginas siguientes**:
   - Cabeceras recomendadas (tabla + gráfico)
   - Cabeceras contextuales (tabla + gráfico)
   - Cabeceras obsoletas (tabla + gráfico)
   - Certificados (tabla + gráfico + recomendaciones)
   - Cookies (si existen)

---

## 🔍 Recomendaciones Post-Evaluación

Si el informe identifica problemas:

1. **Certificados de corta duración**: Implementar ACME o API REST para automatizar
2. **Cabeceras faltantes**: Configurar servidor web (Nginx, Apache, IIS)
3. **Cookies inseguras**: Añadir flags Secure, HttpOnly, SameSite
4. **Información expuesta**: Ocultar versiones de servidor y tecnologías

---

## 📧 Contacto y Soporte

Proyecto de prácticas de TSS en Ciberseguridad

**Autor**: Ángel Deza

---

## 📜 Licencia

Uso educativo y profesional - Abierto para modificaciones

---

## 🔄 Versiones Futuras

- [ ] Soporte para múltiples URLs
- [ ] Base de datos de resultados históricos
- [ ] Exportación a JSON/CSV
- [ ] Integración con herramientas SIEM
- [ ] Dashboard web para visualización
- [ ] Alertas automáticas para certificados próximos a vencer
- [ ] Análisis de vulnerabilidades adicionales

---

**Última actualización**: Febrero 2026
