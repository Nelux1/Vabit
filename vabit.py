import PySimpleGUI as sg
import requests

# Define las claves de API de VirusTotal y AbuseIPDB

VIRUSTOTAL_API_KEY = 'YOUR_API_KEY'
ABUSEIPDB_API_KEY = 'YOUR_API_KEY'

# Función para consultar VirusTotal
def check_virustotal(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    data = response.json()
    return data

# Función para consultar AbuseIPDB
def check_abuseipdb(ip):
    url = f'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': ABUSEIPDB_API_KEY
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'  # Puedes ajustar esto según tus necesidades
    }
    response = requests.get(url, headers=headers, params=params)
    data = response.json()
    return data

# Función para obtener la ubicación completa del país de la IP
def get_ip_location(ip):
    url = f'https://ipinfo.io/{ip}/json'
    response = requests.get(url)
    data = response.json()
    return data.get('country', 'Desconocido')

# Interfaz gráfica con PySimpleGUI
sg.theme('SystemDefault')

layout = [
    [sg.Text('Archivo de texto con IPs:'), sg.InputText(key='file_path'), sg.FileBrowse(file_types=(("Text files", "*.txt"),))],
    [sg.Output(size=(80, 20))],
    [sg.Button('Procesar')]
]

window = sg.Window('Verificador de IPs Maliciosas', layout)

malicious_ips = []  # Lista para almacenar las IPs maliciosas
non_malicious_ips = []  # Lista para almacenar las IPs no maliciosas

while True:
    event, values = window.read()

    if event == sg.WIN_CLOSED:
        break
    elif event == 'Procesar':
        file_path = values['file_path']
        try:
            with open(file_path, 'r') as file:
                ips = file.read().splitlines()

            total_ips = len(ips)

            for ip in ips:
                print(f'Consultando IP: {ip}')
                vt_data = check_virustotal(ip)
                ai_data = check_abuseipdb(ip)

                # Procesar y mostrar los resultados
                if 'data' in vt_data:
                    print('Resultados de VirusTotal:')
                    is_malicious = False
                    for scan, result in vt_data['data']['attributes']['last_analysis_results'].items():
                        print(f'{scan}: {result["result"]}')
                        if 'malicius' in result["result"].lower() or 'phishing' in result["result"].lower() or 'malicious' in result["result"].lower():
                            is_malicious = True

                    if is_malicious:
                        malicious_ips.append((ip, get_ip_location(ip)))  # Agregar la IP maliciosa y su ubicación completa a la lista
                    else:
                        non_malicious_ips.append((ip, get_ip_location(ip)))  # Agregar la IP no maliciosa y su ubicación completa a la lista

                if 'data' in ai_data:
                    print('\nResultados de AbuseIPDB:')
                    print(f'IP: {ai_data["data"]["ipAddress"]}')
                    print(f'Abusos recientes: {ai_data["data"]["totalReports"]}')

                print('\n---')

            print(f'Total de IPs: {total_ips}')
            print('')
            print(f'IPs Maliciosas detectadas por VirusTotal y AbuseIPdb ({len(malicious_ips)}):')
            print('**********************************************')
            for malicious_ip, country in malicious_ips:
                print(f'IP: {malicious_ip}, País: {country}')
            print('')
            print(f'IPs No Maliciosas ({len(non_malicious_ips)}):')
            print('**********************************************')
            for non_malicious_ip, country in non_malicious_ips:
                print(f'IP: {non_malicious_ip}, País: {country}')

        except FileNotFoundError:
            print('Archivo no encontrado.')
        except Exception as e:
            print(f'Ocurrió un error: {str(e)}')

window.close()
