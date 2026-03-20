import socket
import ssl
import requests
import matplotlib.pyplot as plt
from datetime import timedelta, datetime
from fpdf import FPDF
import tldextract
import validators
import logging
import tempfile
import os
import ipaddress
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def extractor_certificado(url_certificado, puerto, timeout):
    """Extrae la información del certificado SSL/TLS de una web dada su url
    
    La función recibe un string con la url de la web, establece una conexión segura y extrae la información
    del certificado SSL/TLS. Procesa las fechas de inicio y vencimiento del certificado,
    además de la versión de TLS utilizada. Finalmente, devuelve un diccionario con
    la información relevante del certificado.

    Parámetros:
    url (str): url de la web a evaluar
    retorna: un diccionario con la información del certificado
    """

    # Se crea un bloque try/except para capturar cualquier error por la introduccion de una url errónea
    try:
        # se crea una variable que sirva de contexto para manejo de la seguridad de la conexión
        contexto = ssl.create_default_context()
        # se establece la conexión mediante un socket
        with socket.create_connection((url_certificado, puerto), timeout) as sock:
            # se envuelve el socket para realizar el handshake
            with contexto.wrap_socket(sock, server_hostname=url_certificado) as ssock:
                # extraemos la información completa del certificado y su versión TLS
                certificado = ssock.getpeercert()
                version_tls = ssock.version()
                # Se procesan las fechas de inicio y vencimiento
                # para obtener la información que requerimos para el infomre en formato datetime
                fecha_inicio = certificado["notBefore"].split()
                fecha_vencimiento = certificado["notAfter"].split()
                str_fecha_inicio = "{}-{}-{}".format(fecha_inicio[1], fecha_inicio[0],fecha_inicio[3])
                str_fecha_vencimiento = "{}-{}-{}".format(fecha_vencimiento[1],fecha_vencimiento[0], fecha_vencimiento[3])
                formato_fecha = "%d-%b-%Y"
                fecha_inicio_dttime = datetime.strptime(str_fecha_inicio, formato_fecha).date()
                fecha_vencimiento_dttime = datetime.strptime(str_fecha_vencimiento, formato_fecha).date()

                # Se crea un diccionario con la información que necesitamos para la evalucación
                certificado_dict = {"Dias de validez": fecha_vencimiento_dttime - fecha_inicio_dttime,
                                    "Fecha vencimiento": fecha_vencimiento_dttime - datetime.now().date(),
                                    "Version SSL/TLS": version_tls,
                                    "Web evaluada": url_certificado}

                # Se retorna el diccionario con la información ya procesada.
                return certificado_dict

    except (socket.timeout, ssl.SSLError, OSError) as e:
        logger.error("Error al obtener certificado de %s: %s", url_certificado, e)
        return None

def extractor_cabeceras(url_original):
    """ Extrae las cabeceras HTTP y cookies de la web URL facilitada.

    Le función recibe un string con la url de la web, realiza una petición HTTP
    para obtener las cabeceras y cookies, las almacena en variables y las retorna en una lista.

    Parámetros:
    url (str): url de la web a evaluar
    """

    try:
        # Se establecen los reintentos en caso de fallos temporales en la conexión o respuestas erróneas del servidor
        intentos = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]) 
        with requests.Session() as session:
            
            # Se montan los adaptadores de HTTP y HTTPS con los reintentos configurados
            session.mount("https://", HTTPAdapter(max_retries=intentos))
            session.mount("http://", HTTPAdapter(max_retries=intentos))

            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                       "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                       "Accept-Language": "es-ES,es;q=0.9",
                       "Connection": "keep-alive",
                       "Upgrade-Insecure-Requests": "1"}

            pagina_web = session.get(url_original, headers=headers, timeout=10, verify=True)
            # Se verifica que la respuesta sea correcta (código 200)
            pagina_web.raise_for_status()
            resp_headers = pagina_web.headers
            resp_cookies = pagina_web.cookies
            

            return [resp_headers, resp_cookies]
        
    except requests.exceptions.HTTPError as errh:
        logger.error(f"Error HTTP: {errh}")
        return None
    except requests.exceptions.ConnectionError as errc:
        logger.error(f"Error de Conexión: {errc}")
        return None
    except requests.exceptions.Timeout as errt:
        logger.error(f"Timeout Error: {errt}")
        return None
    except requests.exceptions.RequestException as err:
        logger.error(f"Error inesperado: {err}")
        return None

def verificador_cabeceras_recomendadas(inf_headers, inf_certificado, conf_x_frame_options, conf_referrer_policy, conf_content_security_policy, conf_cross_origin_opener_policy, conf_cross_origin_resource_policy, conf_permissions_policy):
    """Verifica la presencia de cabeceras HTTP recomendadas y su configuración básica.
    
    La función obtiene las cabeceras de la web mediante la función extractor_cabeceras,
    luego verifica la presencia de cabeceras HTTP recomendadas y su configuración básica, almacenando
    los resultados en un diccionario y contabilizando las configuraciones correctas e incorrectas en dos variables.
    Devuelve una lista con el diccionario de resultados y los contadores. 

    Parámetros:
    url (str): url de la web a evaluar"""

    # Se crea el diccionario donde se almacena el valor de las evaluaciones.
    # Criterio: se evalua permanencia y configuración básica de las cabeceras,
    # siendo True para cabeceras presentes con configuraciones básicas que se cumplen y False para las que no están presentes o no cumplen.
    dict_eval_head_recomendados = {"x-frame-options": False if not "x-frame-options" in inf_headers else True,
                       "referrer-policy": False if not "referrer-policy" in inf_headers else True,
                       "x-content-type-options": False if not "x-content-type-options" in inf_headers else True,
                       "strict-transport-security (hsts)": False if not "strict-transport-security" in inf_headers else True,
                       "content-security-policy (csp)": False if not "content-security-policy" in inf_headers else True,
                       "access-control-allow-origin": False if not "access-control-allow-origin" in inf_headers else True,
                       "cross-origin-opener-policy": False if not "cross-origin-opener-policy" in inf_headers else True,
                       "cross-origin-embedder-policy": False if not "cross-origin-embedder-policy" in inf_headers else True,
                       "cross-origin-resource-policy": False if not "cross-origin-resource-policy" in inf_headers else True,
                       "permissions-policy": False if not "permissions-policy" in inf_headers else True}
    for clave, valor in inf_headers.items():
        if clave == "x-frame-options":
            if valor.strip().lower() == conf_x_frame_options.strip().lower():   
                dict_eval_head_recomendados["x-frame-options"] = True
            else:
                dict_eval_head_recomendados["x-frame-options"] = False
        elif clave == "referrer-policy":
            if valor.strip().lower() == conf_referrer_policy.strip().lower():
                dict_eval_head_recomendados["referrer-policy"] = True
            else:
                dict_eval_head_recomendados["referrer-policy"] = False
        elif clave == "x-content-type-options":
            if valor.strip().lower() == "nosniff":
                dict_eval_head_recomendados["x-content-type-options"] = True
            else:
                dict_eval_head_recomendados["x-content-type-options"] = False
        elif clave == "strict-transport-security":
            if "max-age" in valor.lower() and "includesubdomains" in valor.lower():
                dict_eval_head_recomendados["strict-transport-security (hsts)"] = True
            else:
                dict_eval_head_recomendados["strict-transport-security (hsts)"] = False
        elif clave == "content-security-policy":
            conf_recomendada = {s.strip().lower() for s in set(conf_content_security_policy.split(";"))}
            conf_actual = {s.strip().lower() for s in set(valor.split(";"))}
            cumplimiento = set()
            for i in conf_actual:
                if i.strip().lower() in conf_recomendada:
                    cumplimiento.add(i.strip().lower())
                else:
                    pass
            if cumplimiento == conf_recomendada:
                dict_eval_head_recomendados["content-security-policy (csp)"] = True
            else:
                dict_eval_head_recomendados["content-security-policy (csp)"] = False
        elif clave == "access-control-allow-origin":
            if valor.strip().lower() in ["https://"+inf_certificado["Web evaluada"], "http://"+inf_certificado["Web evaluada"]]:
                dict_eval_head_recomendados["access-control-allow-origin"] = True
            else:
                dict_eval_head_recomendados["access-control-allow-origin"] = False
        elif clave == "cross-origin-opener-policy":
            if valor.lower().strip() == conf_cross_origin_opener_policy.lower().strip():
                dict_eval_head_recomendados["cross-origin-opener-policy"] = True
            else:
                dict_eval_head_recomendados["cross-origin-opener-policy"] = False
        elif clave == "cross-origin-embedder-policy":
            if valor.lower() == "require-corp":
                dict_eval_head_recomendados["cross-origin-embedder-policy"] = True
            else:
                dict_eval_head_recomendados["cross-origin-embedder-policy"] = False
        elif clave == "cross-origin-resource-policy":
            if valor.lower() == conf_cross_origin_resource_policy.lower().strip():
                dict_eval_head_recomendados["cross-origin-resource-policy"] = True
            else:
                dict_eval_head_recomendados["cross-origin-resource-policy"] = False
        elif clave == "permissions-policy":
            conf_recomendada = {s.lower().strip() for s in set(conf_permissions_policy.split(","))}
            conf_actual = set(valor.split(","))
            cumplimiento = set()
            for i in conf_actual:
                if i.strip().lower() in conf_recomendada:
                    cumplimiento.add(i.strip().lower())
                else:
                    pass
            if cumplimiento == conf_recomendada:
                dict_eval_head_recomendados["permissions-policy"] = True
            else:
                dict_eval_head_recomendados["permissions-policy"] = False
        else:
            pass

    # Variables para sumatoria de configuraciones correctas e incorrectas
    contador_conf_correcta = 0
    contador_conf_incorrecta = 0

    print("\nEvaluación de Security Headers recomendados:\n")
    for clave, valor in dict_eval_head_recomendados.items():
        if valor == True:
            contador_conf_correcta += 1
            print("Recomendados {} ---> {}".format(clave, valor))
        else:
            contador_conf_incorrecta += 1
            print("Recomendados {} ---> {}".format(clave, valor))

    return [dict_eval_head_recomendados, contador_conf_correcta, contador_conf_incorrecta]

def verificador_cabeceras_contextuales(inf_headers):
    """Verifica la presencia de cabeceras HTTP contextuales que no se recomienda que sean visibles.
    
    La función obtiene las cabeceras de la web mediante la función extractor_cabeceras, y luego verifica si la url 
    contiene cabeceras HTTP contextuales que no se recomienda que sean visibles, almacenando los resultados en un diccionario y contabilizando
    las configuraciones correctas e incorrectas en dos variables. Devuelve una lista con el diccionario de resultados y los contadores.
    
    Parámetros:
    inf_headers (dict): cabeceras de la web a evaluar
    """

    # Se crea el diccionario donde se almacena el valor de las evaluaciones.
    # Criterio para Headers contextuales: se evalua True para cabeceras no presentes y False para las que están presentes.
    dict_eval_head_contextuales = {"x-powered-by": False if "x-powered-by" in inf_headers else True,
                                   "x-aspnet-version": False if "x-aspnet-version" in inf_headers else True,
                                   "x-aspnetmvc-version": False if "x-aspnetmvc-version" in inf_headers else True,
                                   "server": False if "server" in inf_headers else True}

    # Se crean dos contadores que sirvan para llevar la sumatoria de las
    # configuraciones que se han hecho correcta e incorrectamente.
    contador_conf_correcta = 0
    contador_conf_incorrecta = 0

    # Se recorren los diccionarios para almacenar la cantidad de estandares que se cumplen y los que no.
    print("\nEvaluación de Security Headers contextuales:\n")
    for clave, valor in dict_eval_head_contextuales.items():
        if valor == True:
            contador_conf_correcta += 1
            print("contextuales {} ---> {}".format(clave, valor))
        else:
            contador_conf_incorrecta += 1
            print("contextuales {} ---> {}".format(clave, valor))

    return [dict_eval_head_contextuales, contador_conf_correcta, contador_conf_incorrecta]

def verificador_cabeceras_obsoletas(inf_headers):
    """Verifica la presencia de cabeceras HTTP obsoletas.
    
    La función obtiene las cabeceras de la web mediante la función extractor_cabeceras,
    luego verifica si la url contiene cabeceras HTTP obsoletas, almacenando
    los resultados en un diccionario y contabilizando las configuraciones correctas e incorrectas en dos variables.
    Devuelve una lista con el diccionario de resultados y los contadores.
    
    Parámetros:
    inf_header (dict): cabeceras de la web a evaluar
    """

    # Se crea el diccionario donde se almacena el valor de las evaluaciones.
    # Criterio para Headers obsoletos: se evalua True para cabeceras no presentes y False para las que están presentes.
    dict_eval_head_obsoletos = {"x-xss-protection": False if "x-xss-protection" in inf_headers else True,
                                "expect-ct": False if "expect-ct" in inf_headers else True,
                                "feature-policy": False if "feature-policy" in inf_headers else True,
                                "pragma": False if "pragma" in inf_headers else True,
                                "public-key-pins": False if "public-key-pins" in inf_headers else True} 
    # Se crean dos contadores que sirvan para llevar la sumatoria de las
    # configuraciones que se han hecho correcta e incorrectamente.
    contador_conf_correcta = 0
    contador_conf_incorrecta = 0
    # Se recorren los diccionarios para almacenar la cantidad de estandares que se cumplen y los que no.
    print("\nEvaluación de Security Headers obsoletos:\n")
    for clave, valor in dict_eval_head_obsoletos.items():
        if valor == True:
            contador_conf_correcta += 1
            print("Obsoleto {} ---> {}".format(clave, valor))
        else:
            contador_conf_incorrecta += 1
            print("Obsoleto {} ---> {}".format(clave, valor))

    return [dict_eval_head_obsoletos, contador_conf_correcta, contador_conf_incorrecta]

def verificador_certificados(inf_certificado, conf_tiempo_vencimiento_minimo):
    """Verifica la seguridad del certificado SSL/TLS de la web.
    
    La función obtiene la información del certificado SSL/TLS de la web mediante la función extractor_certificado,
    luego verifica si la url cumple con los estándares básicos de seguridad en cuanto a la versión de TLS y
    el tiempo restante para el vencimiento del certificado y el plazo máximo de validez del certificado. 
    Almacena los resultados de versión de certificado y vencimiento en un diccionario, una lista con que almacena el plazo máximo de validez 
    y una variable booleana indicando si cumple con futuros estándares y, por último, las configuraciones correctas e incorrectas en dos variables.
    
    Devuelve una lista con el diccionario de resultados, la lista con la evaluación de plazo máximo y los contadores.

    Parámetros:
    inf_certificado (dict): información del certificado SSL/TLS de la web a evaluar.
    """

    # Se crea el diccionario donde se almacena el valor de las evaluaciones.
    # Criterio: se evalua True para versión TLS 1.2 o superior y tiempo de vencimiento mayor a 30 días, siendo False para las que no cumplen.
    dict_eval_certificados = {"Certificado SSL/TLS": True if inf_certificado['Version SSL/TLS'] in ["TLSv1.2", "TLSv1.3"] else False,
                              "Vencimiento": True if inf_certificado['Fecha vencimiento'] >= timedelta(days=conf_tiempo_vencimiento_minimo) else False}
    
    # Se crean las dos variables para contabilizar las configuraciones correctas e incorrectas.
    contador_conf_correcta = 0
    contador_conf_incorrecta = 0

    # Se recorren los diccionarios para almacenar la cantidad de estandares que se cumplen y los que no.
    print("\nEvaluación de Certificados:\n")
    for clave, valor in dict_eval_certificados.items():
        if valor == True:
            contador_conf_correcta += 1
            print("Certificado {} ---> {}".format(clave, valor))
        else:
            contador_conf_incorrecta += 1
            print("Certificado {} ---> {}".format(clave, valor))

    # Se verifica la validez máxima del certificado para comprobar que cumple futuros estandares
    certif_nuevos_estand = [False if inf_certificado['Dias de validez'] >= timedelta(days=90) else True, inf_certificado['Dias de validez']]

    return [dict_eval_certificados, certif_nuevos_estand, contador_conf_correcta, contador_conf_incorrecta]

def verificar_cookies(inf_cookies):
    """Verifica la configuración de seguridad de las cookies de la web.
    
    La función obtiene las cookies de la web mediante la función extractor_cabeceras,
    luego verifica la configuración de seguridad de las cookies, almacenando los resultados en una lista de diccionarios
    y contabilizando las configuraciones correctas e incorrectas en dos variables.
    
    Devuelve una lista con los diccionarios de resultados y los contadores.
    
    Parámetros:
    inf_cookies (RequestsCookieJar): cookies de la web a evaluar.
    """

    # Se crean dos contadores que sirvan para llevar la sumatoria de las
    # configuraciones que se han hecho correcta e incorrectamente.
    contador_conf_correcta = 0
    contador_conf_incorrecta = 0

    print("\nEvaluación de atributos de cookies:\n")
    # Se crea una lista de diccionarios con la información de cada cookie
    list_cookies = []
    for i in inf_cookies:
        temp_dic = {"Nombre cookie": i.name, "Secure": i.secure, "HttpOnly": i.has_nonstandard_attr('HttpOnly'),
                    "Samesite": False if i.get_nonstandard_attr('SameSite') == None else True}
        list_cookies.append(temp_dic)
    if not list_cookies:
        print("No se han detectado cookies")
    # Se recorren los diccionarios para almacenar la cantidad de estandares que se cumplen y los que no.
    for i in list_cookies:
        for claves, valores in i.items():
            if claves == "Nombre cookie":
                continue
            elif valores == True:
                contador_conf_correcta += 1
                print(claves, valores)
            else:
                contador_conf_incorrecta += 1
                print(claves, valores)

    return [list_cookies, contador_conf_correcta, contador_conf_incorrecta]

def validador_url(url):
    """Valida que la url proporcionada es correcta.

    La función utiliza la librería validators para comprobar que la url proporcionada
    es válida y completa, devolviendo un listado con dos variables: un string de la url modificada para ser compatible
    con las librerías socket y ssl y un string con la url original para ser compatible con requests.

    Parámetros:
    url (str): url de la web a evaluar
    retorna: list: [url modificada, url original]
    """
    try:
        if validators.url(url) == True:
            # Se crea un bloque if/else para trasnformar la url
            # a un formato que sea manejable por las librerías socket y ssl, eliminando las subcadenas http:// y https://
            url_dividido = tldextract.extract(url)
            if url_dividido.subdomain == "":
                url_certificado = url_dividido.domain + "." + url_dividido.suffix
            else:
                url_certificado = url_dividido.subdomain + "." + url_dividido.domain + "." + url_dividido.suffix
            return [url_certificado, url]

        else:
            print("Formato de url inválido. Por favor, verifique que se incluye la url completa.")

    except Exception as e:
        logger.error(f"Ha ocurrido el error {e}")
        return None

def creador_gráfico_torta(contador_conf_correcta, contador_conf_incorrecta, carpeta_temp):
    """Crea un gráfico de torta con los resultados de la evaluación de seguridad.

    La función recibe los contadores de configuraciones correctas e incorrectas,
    y genera un archívo png con el gráfico de torta para visualizar los resultados.

    Devuelve un archivo png con el gráfico de torta en una carpeta temporal que se elimina al finalizar la ejecución del programa.

    Parámetros:
    contador_conf_correcta (int): número de configuraciones correctas
    contador_conf_incorrecta (int): número de configuraciones incorrectas
    carpeta_temp (str): ruta de la carpeta temporal para almacenar el gráfico
    """

    try:

        fig, ax = plt.subplots(figsize=(6,6), subplot_kw=dict(aspect="equal"))
        etiquetas = ['Correctas', 'Incorrectas']
        valores = [contador_conf_correcta, contador_conf_incorrecta]
        ax.pie(valores, labels=etiquetas, autopct='%1.1f%%', startangle=90, colors=['#C8FFC8', "#FFC8C8"])
        ax.set_title("Evaluación de seguridad web")
        plt.savefig(os.path.join(carpeta_temp, "grafico_principal.png"))
        plt.close()

    except Exception as e:
        logger.error(f"Error al crear gráfico de torta: {e}")
        return None

def creador_grafico_barras(titulo, valores_correctos, valores_incorrectos, carpeta_temp):
    """Crea un gráfico de barras con los resultados de la evaluación de seguridad de cada categoría.

    La función recibe un título y dos variables de tipo int con los valores de configuraciones correctas e incorrectas de cada categoría,
    y genera un archivo png con el gráfico de barras para visualizar los resultados de esa categoría.

    Devuelve un archivo png con el gráfico de barras en una carpeta temporal que se elimina al finalizar la ejecución del programa.

    Parámetros:
    titulo (str): título del gráfico o categoría evaluada
    valores_correctos (int): número de configuraciones correctas
    valores_incorrectos (int): número de configuraciones incorrectas
    carpeta_temp (str): ruta de la carpeta temporal para almacenar el gráfico
    """

    try:
        fig, ax = plt.subplots(figsize=(6,4))
        etiquetas = ['Correctas', 'Incorrectas']
        valores = [valores_correctos, valores_incorrectos]
        ax.bar(etiquetas, valores, color=['#C8FFC8', "#FFC8C8"])
        ax.set_title(titulo)
        plt.savefig(os.path.join(carpeta_temp, f"{titulo}.png"))
        plt.close()

    except Exception as e:
        logger.error(f"Error al crear gráfico de barras: {e}")
        return None

def creador_informe_pdf(eval_head_recomendados, eval_head_contextuales, eval_head_obsoletos, eval_certificados, eval_cookies, contador_conf_correcta, contador_conf_incorrecta, url_certificado):
    """Crea un informe de seguridad en formato PDF.

    La función recopila la información obtenida de las evaluaciones de seguridad
    y genera un informe en formato PDF con los resultados.

    Parámetros:
    eval_head_recomendados (list): resultados de la evaluación de cabeceras recomendadas
    eval_head_contextuales (list): resultados de la evaluación de cabeceras contextuales
    eval_head_obsoletos (list): resultados de la evaluación de cabeceras obsoletas
    eval_certificados (list): resultados de la evaluación de certificados
    eval_cookies (list): resultados de la evaluación de cookies
    contador_conf_correcta (int): número de configuraciones correctas
    contador_conf_incorrecta (int): número de configuraciones incorrectas
    url_certificado (str): url de la web evaluada

    retorna: un archivo PDF con el informe de seguridad
    """

    # Se crean una lista con los títulos de las secciones y otra con las evalucaciones correspondientes
    titulos = ["Evaluación de cabeceras recomendadas", "Evaluación de cabeceras contextuales",
               "Evaluación de cabeceras obsoletas", "Evaluación de certificados", "Evaluación de cookies"]
    cabeceras_evaluadas = [eval_head_recomendados[0], eval_head_contextuales[0], eval_head_obsoletos[0], eval_certificados[0], eval_cookies[0]]

    # Se crea una carpeta temporal para almacenar los gráficos generados
    with tempfile.TemporaryDirectory() as carpeta_temp:

    # Se crean los gráficos necesarios para el informe
        creador_gráfico_torta(contador_conf_correcta, contador_conf_incorrecta, carpeta_temp)
        creador_grafico_barras(titulos[0], eval_head_recomendados[1], eval_head_recomendados[2], carpeta_temp)
        creador_grafico_barras(titulos[1], eval_head_contextuales[1], eval_head_contextuales[2], carpeta_temp)
        creador_grafico_barras(titulos[2], eval_head_obsoletos[1], eval_head_obsoletos[2], carpeta_temp)
        creador_grafico_barras(titulos[3], eval_certificados[2], eval_certificados[3], carpeta_temp)
        if eval_cookies[0] == []:
            pass
        else:
            creador_grafico_barras(titulos[4], eval_cookies[1], eval_cookies[2], carpeta_temp)

    # Se crea el informe en PDF
    # Configuración inicial del PDF, 
        class ReportePDF(FPDF):
            def header(self):
                self.set_font("Helvetica", "B", 14)
                self.multi_cell(0, 10, "Reporte de Postura de Seguridad web:\n{}".format(url_certificado), align ="C")
                self.ln(10)

            def footer(self):
                self.set_y(-15)
                self.set_font("Helvetica", "I", 8)
                self.cell(0, 10, "Página {}".format(self.page_no()), align="C")
            
        pdf = ReportePDF()
        try:
            # Se agrega una fuente que permita mostrar los caracteres de check y warning
            pdf.add_font("DejaVu", fname="fuente\DejaVuSans.ttf", uni=True) 
        
        except Exception as e:
            logger.error(f"Error al cargar la fuente: {e}")
            return None

        pdf.add_page()
        # Se inserta el gráfico en la primera página
        pdf.image(f"{carpeta_temp}\grafico_principal.png", x= 40, y= 100, w=125, h=125)
        pdf.ln(10) # Espacio después del gráfico
        pdf.multi_cell(0, 10, "Resumen de la evaluación de seguridad web:\nConfiguraciones correctas: {}\nConfiguraciones incorrectas: {}".format(contador_conf_correcta, contador_conf_incorrecta), align='C')
        pdf.add_page()

        # Se inserta la tabla de dos columnas y el gráfico correspondiente para cada sección
        col_width = pdf.w / 2 - 10  # Ancho de cada columna
        for i in titulos:
            if i == "Evaluación de cookies" and eval_cookies[0] == []:
                continue
            elif i == "Evaluación de cookies":
                pdf.image(f"{carpeta_temp}\{i}.png", w=125, h= 75, x= 45)
                pdf.ln(10)
                pdf.set_font("Helvetica", size=12)
                pdf.cell(0, 10, '{}'.format(i), 0, 1, 'C')
            
            # Datos de las cookies
                for cookie in cabeceras_evaluadas[titulos.index(i)]:
                    pdf.set_font("Helvetica", size=12)
                    pdf.cell(0, 10, 'Cookie: {}'.format(cookie["Nombre cookie"]), 0, 1, 'C')
                    pdf.cell(col_width, 10, "Atributo", border=1, align='C')
                    pdf.cell(col_width, 10, "Estado", border=1, align='C', ln=True)
                    for clave, valor in cookie.items():
                        if clave == "Nombre cookie":
                            continue
                        else: 
                            pdf.set_font("Helvetica", size=12)   
                            pdf.cell(col_width, 10, clave, border=1, align='C')
                            if valor == True:
                                pdf.set_fill_color(200, 255, 200)
                                pdf.set_font("DejaVu", size=26)
                                pdf.cell(col_width, 10, "✔", border=1, align='C', ln=True, fill=True)
                            else:
                                pdf.set_fill_color(255, 200, 200)
                                pdf.set_font("DejaVu", size=26)
                                pdf.cell(col_width, 10, "⚠", border=1, align='C', ln=True, fill=True)
                    pdf.ln(10)
            
            elif i == "Evaluación de certificados":
                pdf.image(f"{carpeta_temp}\{i}.png", w=125, h= 75, x= 45)
                pdf.ln(10)
                pdf.set_font("Helvetica", size=12)
                pdf.cell(0, 10, '{}'.format(i), 0, 1, 'C')
                pdf.cell(col_width, 10, "Atributo", border=1, align='C')
                pdf.cell(col_width, 10, "Estado", border=1, align='C', ln=True)
                # Datos del certificado
                for clave, valor in cabeceras_evaluadas[titulos.index(i)].items():
                    pdf.set_font("Helvetica", size=12)
                    pdf.cell(col_width, 10, clave, border=1, align='C')
                    if valor == True:
                        pdf.set_fill_color(200, 255, 200) 
                        pdf.set_font("DejaVu", size=26)
                        pdf.cell(col_width, 10, "✔", border=1, align='C', ln=True, fill = True)
                    else:
                        pdf.set_fill_color(255, 200, 200) 
                        pdf.set_font("DejaVu", size=26)
                        pdf.cell(col_width, 10, "⚠", border=1, align='C', ln=True, fill = True)
                pdf.ln(10)
                if eval_certificados[1][0] == True:
                    pass
                else:
                    pdf.set_font("Helvetica", size=12)
                    pdf.multi_cell(0, 10, "La validez total del certificado es de {} días, lo que podría no ser compatible con futuros estandares.\nSe recomienda la automatización del ciclo de vida de los certificados con herramientas como API REST o ACME".format(eval_certificados[1][1].days))
                pdf.add_page()

            else:
                pdf.image(f"{carpeta_temp}\{i}.png", w=125, h= 75, x= 45)
                pdf.ln(10)
                pdf.set_font("Helvetica", size=12)
                pdf.cell(0, 10, '{}'.format(i), 0, 1, 'C')
                pdf.cell(col_width, 10, "Cabecera", border=1, align='C')
                pdf.cell(col_width, 10, "Estado", border=1, align='C', ln=True)
                for clave, valor in cabeceras_evaluadas[titulos.index(i)].items():
                    pdf.set_font("Helvetica", size=12)
                    pdf.cell(col_width, 10, clave, border=1, align='C')
                    if valor == True:
                        pdf.set_fill_color(200, 255, 200) # Verde claro
                        pdf.set_font("DejaVu", size=26)
                        pdf.cell(col_width, 10, "✔", border=1, align='C', ln=True, fill = True)
                    else:
                        pdf.set_fill_color(255, 200, 200) # Rojo claro
                        pdf.set_font("DejaVu", size=26)
                        pdf.cell(col_width, 10, "⚠", border=1, align='C', ln=True, fill = True)
                pdf.ln(10)
                pdf.add_page()

        pdf.output("{}.pdf".format(url_certificado.replace(".", "_")))
    
def conf_parametros_seguridad_web():
    """Configura los parámetros de seguridad web.

    La función permite al usuario configurar los parámetros de seguridad web
    mediante la entrada de datos por consola. Los parámetros solicitados incluyen
    la URL, el tiempo de espera, el puerto, el tiempo mínimo de vencimiento del certificado,
    y los valores para algunas cabeceras de seguridad.

    Retorna:
    dict: diccionario con los parámetros de seguridad web configurados.
    """

    parametros = {}
    # Se crea un bloque try/except para capturar posibles errores en la entrada de datos y se solicita al usuario la configuración de los parámetros para almacenarlos en un diccionario
    try:
        
        parametros['url'] = input("Ingrese la URL completa de la web a evaluar (incluya http:// o https://): ")
        print("Configuración de parámetros, en caso de no querer modificar alguno, presione Enter:")
        parametros['timeout'] = int(input("Ingrese el tiempo de espera para las solicitudes (en segundos, valor por defecto 10): ") or 10)
        parametros["puerto"] = int(input("Ingrese el puerto para la conexión (valor por defecto 443): ") or 443)
        parametros["tiempo_vencimiento_minimo"] = int(input("Ingrese el tiempo mínimo de vencimiento del certificado (en días, valor por defecto 30): ") or 30)
        parametros["x-frame-options"] = input("Ingrese el valor para X-Frame-Options (por defecto 'DENY'): ") or "DENY"
        parametros["referrer-policy"] = input("Ingrese el valor para Referrer-Policy (por defecto 'no-referrer'): ") or "no-referrer"
        parametros["content-security-policy"] = input("Ingrese las directivas para Content-Security-Policy, recuerde separar cada configuración usando ';' (por defecto las recomendaciones OWASP Secure Headers Project): ") or "default-src 'self'; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests"
        parametros["cross-origin-opener-policy"] = input("Ingrese el valor para Cross-Origin-Opener-Policy (por defecto 'same-origin'): ") or "same-origin"
        parametros["cross-origin-resource-policy"] = input("Ingrese el valor para Cross-Origin-Resource-Policy (por defecto 'same-site'): ") or "same-site"
        parametros["permissions-policy"] = input("Ingrese las directivas para Permissions-Policy, recuerde separar cada configuración usando ',' (por defecto las recomendaciones OWASP Secure Headers Project): ") or "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(), gamepad=(), hid=(), idle-detection=(), interest-cohort=(), serial=(), unload=()"

    except Exception as e:
        logger.error("Error al configurar los parámetros de seguridad web: %s", e)
    print("\nParámetros configurados:")
    for clave, valor in parametros.items():
        print(f"{clave}: {valor}")
    return parametros

def evaluador_seguridad_web():
    """Evalua los parámetros de seguridad básicos de la url.

    La función solicita al usuario la url a evaluar, ejecuta las funciones de verificación
    y actualiza los contadores. Finalmente, extrae la información relevante de los resultados obtenidos,
    la muestra por pantalla y genera un informe de seguridad en PDF.
    """
    # Se solicita al usuario la url a evaluar y las posibles configuraciones personalizadas
    parametros = conf_parametros_seguridad_web()
    url = parametros['url'] 
    timeout = parametros['timeout']
    puerto = parametros['puerto']  
    conf_tiempo_vencimiento_minimo = parametros['tiempo_vencimiento_minimo']
    conf_x_frame_options = parametros['x-frame-options']
    conf_referrer_policy = parametros['referrer-policy']
    conf_content_security_policy = parametros['content-security-policy']
    conf_cross_origin_opener_policy = parametros['cross-origin-opener-policy']
    conf_cross_origin_resource_policy = parametros['cross-origin-resource-policy']
    conf_permissions_policy = parametros['permissions-policy']

    listado_url = validador_url(url)
    if not listado_url:
        print("URL inválida")
        return
    url_certificado, url_original = listado_url[0], listado_url[1]
    # Se extrae la información de cabeceras, cookies y certificados usando las funciones correspondientes
    inf_header_cookies = extractor_cabeceras(url_original)
    if not inf_header_cookies:
        print("No se pudieron obtener headers y cookies de la URL")
        return
    inf_headers = inf_header_cookies[0]
    inf_headers = {k.lower(): v for k, v in inf_headers.items()}
    inf_cookies = inf_header_cookies[1]
    inf_certificado = extractor_certificado(url_certificado, puerto, timeout)
    if not inf_certificado:
        print("No se pudieron obtener informa de la URL")
        return

    # Se ejecutan las funciones de verificación y se actualizan los contadores
    eval_head_recomendados = verificador_cabeceras_recomendadas(inf_headers, inf_certificado, conf_x_frame_options, conf_referrer_policy, conf_content_security_policy, conf_cross_origin_opener_policy, conf_cross_origin_resource_policy, conf_permissions_policy)
    eval_head_contextuales = verificador_cabeceras_contextuales(inf_headers)
    eval_head_obsoletos = verificador_cabeceras_obsoletas(inf_headers)
    eval_certificados = verificador_certificados(inf_certificado, conf_tiempo_vencimiento_minimo)
    eval_cookies = verificar_cookies(inf_cookies)

    # Se extrae la información relevante de los resultados obtenidos
    contador_conf_correcta = sum([eval_head_recomendados[1], eval_head_contextuales[1], eval_head_obsoletos[1], eval_certificados[2], eval_cookies[1]])
    contador_conf_incorrecta = sum([eval_head_recomendados[2], eval_head_contextuales[2], eval_head_obsoletos[2], eval_certificados[3], eval_cookies[2]])

    print("\nConteo de configuraciones:\nCorrectos ---> {}\nIncorrectos---> {}".format(contador_conf_correcta, contador_conf_incorrecta))
    if eval_certificados[1][0] == True:
        pass
    else:
        print("\nLa validez total del certificado es de {} días, lo que podría no ser compatible con futuros estandares. Se recomienda la automatización del ciclo de vida de los certificados con herramientas como API REST o ACME".format(eval_certificados[1][1].days))

    creador_informe_pdf(eval_head_recomendados, eval_head_contextuales, eval_head_obsoletos, eval_certificados, eval_cookies, contador_conf_correcta, contador_conf_incorrecta, url_certificado)

if __name__ == "__main__":
    evaluador_seguridad_web()

