##############################################################
# Autor: Daniel Moreno Leon     DNI: 49093324P
# Asignatura: Seguridad de la Informacion
# Grupo: 3B Ingeniera Informatica (Subgrupo D de practicas)
##############################################################

from funciones_aes import *
from funciones_rsa import *
from socket_class import *
import json
from datetime import datetime


##########################################
# Paso 0: Inicializacion 
# Crear claves privada y publica de TTP
##########################################

# Creamos las claves y guardamos la privada
clave_priv_ttp = crear_RSAKey()

# Y guardamos la clave publica en un fichero .txt
guardar_RSAKey_Publica("clavepublicaTTP.txt", clave_priv_ttp)


########################################
# Paso 1
########################################

# Creamos el socket de escucha de Alice (5551)
print("Esperando a Alice")
socket_Alice_TTP = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket_Alice_TTP.escuchar()

# Recibimos el mensaje de Alice
mensaje_alice = socket_Alice_TTP.recibir()

# Decodificamos el contenido del mensaje
json_recibido = mensaje_alice.decode("utf-8", "ignore")
datos_cifrados, datos_firmados = json.loads(json_recibido)
datos_cifrados = bytearray.fromhex(datos_cifrados)
datos_firmados = bytearray.fromhex(datos_firmados)

# Desciframos los datos
datos_descifrados = descifrarRSA_OAEP(datos_cifrados, clave_priv_ttp)
print("Paso 1. Alice -> TTP (descifrado): " + datos_descifrados)

# Extraemos el contenido y lo guardamos
ts_a, KAT = json.loads(datos_descifrados)
KAT = bytearray.fromhex(KAT) # Clave Alice-TTP

# Cargamos la clave publica de Alice que tenemos guardada en el fichero .txt
clave_pub_Alice = cargar_RSAKey_Publica("clavepublicaAlice.txt")

# Comprobamos que la firma de Alice sea valida
if(comprobarRSA_PSS(KAT, datos_firmados, clave_pub_Alice)):
    print("La firma de Alice es valida")
    
    # Iniciamos el engine de AES para la clave KAT
    engine_aes_KAT = iniciarAES_GCM(KAT)

else:
    print("La firma de Alice no es valida")
    
    # Como hemos detectado que la firma de Alice no es valida, podria tratarse de una intrusion o un ataque, por lo que por precaucion cerramos la conexion
    socket_Alice_TTP.cerrar()    


########################################
# Paso 2
########################################

# Creamos el socket de escucha de Bob (5552)
print("Esperando a Bob")
socket_Bob_TTP = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket_Bob_TTP.escuchar()

# Recibimos el mensaje de Alice
mensaje_Bob = socket_Bob_TTP.recibir()

# Decodificamos el contenido del mensaje
json_recibido = mensaje_Bob.decode("utf-8", "ignore")
datos_cifrados, datos_firmados = json.loads(json_recibido)
datos_cifrados = bytearray.fromhex(datos_cifrados)
datos_firmados = bytearray.fromhex(datos_firmados)

# Desciframos los datos
datos_descifrados = descifrarRSA_OAEP(datos_cifrados, clave_priv_ttp)
print("Paso 2. Bob -> TTP (descifrado): " + datos_descifrados)

# Extraemos el contenido y lo guardamos
ts_b, KBT = json.loads(datos_descifrados)
KBT = bytearray.fromhex(KBT) # Clave Bob-TTP

# Cargamos la clave publica de Alice que tenemos guardada en el fichero .txt
clave_pub_Bob = cargar_RSAKey_Publica("clavepublicaBob.txt")

# Comprobamos que la firma de Alice sea valida
if(comprobarRSA_PSS(KBT, datos_firmados, clave_pub_Bob)):
    print("La firma de Bob es valida")
    
    # Iniciamos el engine de AES para la clave KBT
    engine_aes_KBT = iniciarAES_GCM(KBT)

else:
    print("La firma de Alice no es valida")
    
    # Como hemos detectado que la firma de Bob no es valida, podria tratarse de una intrusion o un ataque, por lo que por precaucion cerramos todas las conexiones abiertas
    socket_Bob_TTP.cerrar()
    socket_Alice_TTP.cerrar()
    
# Como ya no necesitamos el socket de Bob, lo cerramos
socket_Bob_TTP.cerrar()


########################################
# Paso 3
########################################

# Recibimos el mensaje de Alice
mensaje_alice = socket_Alice_TTP.recibir()

# Decodifico el contenido
json_recibido = mensaje_alice.decode("utf-8", "ignore")
print("Paso 3. Alice -> TTP: " + json_recibido)

# Extraemos el contenido y lo guardamos
ts_a, ts_b = json.loads(json_recibido)
print(ts_a + " quiere establecer una comunicacion con " + ts_b)


########################################
# Paso 4
########################################

# Creamos la clave simetrica para Alice y Bob
KAB = crear_AESKey()

# Creamos un mensaje para Alice
mensaje = [] #Array vacio
ts_inicio = datetime.timestamp(datetime.now())
mensaje.append(ts_inicio) 
mensaje.append(KAB.hex()) # Conversion de Bytes a Hexadecimal

# Ciframos informacion en el mensaje de Alice que va dirigida a Bob
mensaje_Bob = []
mensaje_Bob.append(ts_inicio)
mensaje_Bob.append(KAB.hex())
jStr = json.dumps(mensaje_Bob)
json_bob_cifrado, mac_cifrado_bob, nonce_cifrado_bob = cifrarAES_GCM(engine_aes_KBT, jStr.encode("utf-8"))

# Completamos el mensaje que habiamos creado para Alice con la informacion ya cifrada
mensaje.append(json_bob_cifrado.hex())
jStr = json.dumps(mensaje)

# Y ciframos el mensaje completo
json_alice_cifrado, mac_cifrado_alice, nonce_cifrado_alice = cifrarAES_GCM(engine_aes_KAT, jStr.encode("utf-8"))

# Enviamos los mensajes con los nonce y mac que necesita Alice para poder descifrarlo
print("Envio de paso 4")
socket_Alice_TTP.enviar(json_alice_cifrado)
socket_Alice_TTP.enviar(nonce_cifrado_alice)
socket_Alice_TTP.enviar(mac_cifrado_alice)

# Enviamos ahora tambien el nonce y mac que Bob necesita para poder descifrar
socket_Alice_TTP.enviar(nonce_cifrado_bob)
socket_Alice_TTP.enviar(mac_cifrado_bob)

# Como no vamos a necesitar ya la conexion con Alice, cerramos la conexion
socket_Alice_TTP.cerrar()