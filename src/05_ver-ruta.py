import json
import requests
import time

def ip_por_hostname(hostname, api_url_base, headers):
    objetivo = hostname.strip().lower()

    # Busca en hosts
    resp_hosts = requests.get(f"{api_url_base}/host", headers=headers)
    if resp_hosts.status_code == 200:
        for host in resp_hosts.json().get("response", []):
            if host.get("hostName", "").lower() == objetivo:
                return host.get("hostIp")

    # Busca en dispositivos de red
    resp_devs = requests.get(f"{api_url_base}/network-device", headers=headers)
    if resp_devs.status_code == 200:
        for dev in resp_devs.json().get("response", []):
            if dev.get("hostname", "").lower() == objetivo:
                return dev.get("managementIpAddress")

    return None


#api_url_base = "http://172.16.0.4/api/v1" #INTERNO
api_url_base = "http://127.0.0.1:58000/api/v1" #POR NAVEGADOR
#Credenciales del NetworkController
usuario = input('Ingrese usuario del controlador: ')
pwd = input('Ingrese password del controlador: ')

#Proceso de Autenticacion - Se el auth-token para el resto de consultas del proceso
ticket_auth = requests.post(
	f"{api_url_base}/ticket",
	headers={"content-type": "application/json"},
	data=json.dumps({"username": usuario, "password": pwd})
)
if ticket_auth.status_code not in (200, 201):
	print("No se pudo autenticar al usuario:", ticket_auth.status_code, ticket_auth.text)
	exit()

ticket = ticket_auth.json()["response"]["serviceTicket"]
headers = {
	"content-type": "application/json",
	"X-Auth-Token": ticket
}
# Aca se elije el modo de busqueda,
print('Elija el modo de busqueda (0 - POR IP, 1 - POR HOSTNAME')
#modo = 1
modo = int(input())
if modo == 1:
	print('Inserte el Hostname de la maquina de origen: ')
	origen = input()
	print('Inserte el Hostname de la maquina de destino: ')
	destino= input()
	ip_origen = ip_por_hostname(origen, api_url_base, headers)
	ip_destino = ip_por_hostname(destino, api_url_base, headers)
elif modo == 0:
	print('Inserte la IP de la maquina de origen: ')
	ip_origen = input()
	print('Inserte la IP de la maquina de destino: ')
	ip_destino = input()
else:
	exit()


# PathTrace
body_json = {
    "sourceIP": ip_origen,
    "destIP": ip_destino
}
post_resp = requests.post(f"{api_url_base}/flow-analysis", data=json.dumps(body_json), headers=headers)
print("Iniciando Path Trace - Codigo ", post_resp.status_code)
flow_id = post_resp.json()["response"]["flowAnalysisId"]

status = "INPROGRESS"
result_json = {}
# Mientras este en progreso el path trace se va consultando hasta que diga COMPLETED
while status == "INPROGRESS":
    time.sleep(2)
    get_resp = requests.get(f"{api_url_base}/flow-analysis/{flow_id}", headers=headers)
    result_json = get_resp.json()["response"]
    status = result_json["request"]["status"]
#Una vez completado se muestra el recorrido del paquete
if status == "COMPLETED":
    print("\n--- Recorrido ---")
    for nodo in result_json["networkElementsInfo"]:
        nombre = nodo.get("name", "Desconocido")
        ip = nodo.get("ip", "-")
        tipo = nodo.get("type", "-")

		# Obtengo las interfaces de entrada y salida
        in_if = ((nodo.get("ingressInterface") or {}).get("physicalInterface") or {}).get("name", "-")
        out_if = ((nodo.get("egressInterface") or {}).get("physicalInterface") or {}).get("name", "-")

        print(f"[{tipo}] {nombre} ({ip}) | Entrada: {in_if} -> Salida: {out_if}")
else:
    print("Error de Path Trace:", result_json["request"].get("failureReason", "Sin detalle"))
requests.delete(f"{api_url_base}/flow-analysis/{flow_id}", headers=headers)
requests.delete(f"{api_url_base}/ticket/{ticket}", headers=headers)
