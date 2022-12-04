##############################################################
# Autor: Daniel Moreno Leon     DNI: 49093324P
# Asignatura: Seguridad de la Informacion
# Grupo: 3B Ingeniera Informatica (Subgrupo D de practicas)
##############################################################

from funciones_aes import *
from funciones_rsa import *
from socket_class import *
import json


##########################################
# Paso 0: Inicializacion 
# Crear claves privada y publica de Alice
##########################################

# Creamos las claves y guardamos la privada
clave_priv_bob = crear_RSAKey()

# Y guardamos la clave publica en un fichero .txt
guardar_RSAKey_Publica("clavepublicaBob.txt", clave_priv_bob)


##########################################
# Paso 2
##########################################

# Creamos la clave simetrica KBT (Bob-TTP)
KBT = crear_AESKey()

# Establecemos la conexion con la TTP
print("Creando conexion con la TTP")
socket_Bob_TTP = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket_Bob_TTP.conectar()

# Creamos el mensaje y lo mostramos
mensaje = [] #Array vacio
mensaje.append("Bob") 
mensaje.append(KBT.hex()) # Conversion de Bytes a Hexadecimal
jStr = json.dumps(mensaje) # Covertimos un Array Python a String
print("Paso 2. Bob -> TTP (descifrado): " + jStr)


# Cargamos la clave publica de la TTP que tenemos guardada en el fichero .txt
publica_ttp = cargar_RSAKey_Publica("clavepublicaTTP.txt")

# Ciframos el mensaje con la clave publica de la TTP obtenida anteriormente
mensaje_cifrado = cifrarRSA_OAEP(jStr, publica_ttp)

# Firmamos la clave KBT
KBT_firmado = firmarRSA_PSS(KBT, clave_priv_bob)

# Creamos el mensaje completo que vamos a enviar
mensaje = [] #Array vacio
mensaje.append(mensaje_cifrado.hex()) 
mensaje.append(KBT_firmado.hex()) # Conversion de Bytes a Hexadecimal
jStr = json.dumps(mensaje) # Covertimos un Array Python a String

# Enviamos el mensaje
print("Envio de paso 2")
socket_Bob_TTP.enviar(jStr.encode("utf-8"))

# Como no necesitamos ya la conexion con la TTP, cerramos esta conexion
socket_Bob_TTP.cerrar()


#################################################
# Paso 5
#################################################

# Establecemos la conexion con Bob

print("Esperando la conexion con Alice")
socket_Alice_Bob = SOCKET_SIMPLE_TCP('127.0.0.1', 5553)
socket_Alice_Bob.escuchar()

# Esperamos y recibimos la respuesta de la TTP
mensaje_cifrado_alice = socket_Alice_Bob.recibir()
nonce_cifrado_bob = socket_Alice_Bob.recibir()
mac_cifrado_bob = socket_Alice_Bob.recibir()
nonce_cifrado = socket_Alice_Bob.recibir()
mac_cifrado = socket_Alice_Bob.recibir()

# Decodificamos el mensaje recibido
json_recibido = mensaje_cifrado_alice.decode("utf-8", "ignore")
KBTcifrado, KABcifrado = json.loads(json_recibido)
KBTcifrado = bytearray.fromhex(KBTcifrado)
KABcifrado = bytearray.fromhex(KABcifrado)

# Desciframos los daros recibidos en el primer mensaje
datos_descifrados = descifrarAES_GCM(KBT, nonce_cifrado_bob, KBTcifrado, mac_cifrado_bob)

# Obtenemos la clave KAB
json_recibido = datos_descifrados.decode("utf-8", "ignore")
print("Paso 5. Alice -> Bob (descifrado): " + json_recibido)

ts_ttp, KAB = json.loads(json_recibido)
KAB = bytearray.fromhex(KAB)

# Desciframos los datos del segundo mensaje que hemos obtenido con la clave KAB
datos_descifrados = descifrarAES_GCM(KAB, nonce_cifrado, KABcifrado, mac_cifrado)

# Decodificamos el contenido
json_recibido = datos_descifrados.decode("utf-8", "ignore")
print("Paso 5. Alice -> Bob (descifrado): " + json_recibido)

# Extraemos los datos recibidos
t_a, ts_alice = json.loads(json_recibido)

#Comprobamos los timestamps
if(ts_ttp == ts_alice):
    print("El timestamp es correcto")
    
else:
    print("El timestamp no es correcto")
    
    # Como hemos detectado que la respuesta al mensaje enviado a Bob no es correcta, podria tratarse de una intrusion o un ataque, por lo que por precaucion cerramos la conexion
    socket_Alice_Bob.cerrar()


#################################################
# Paso 6
#################################################

# Iniciamos el engine de AES para la clave KAB
engine_aes_KAB = iniciarAES_GCM(KAB)


# Creamos el mensaje que vamos a enviar
mensaje = ts_alice + 1
jStr = json.dumps(mensaje) # Covertimos un Array Python a String

# Ciframos el mensaje con la clave KAB
mensaje_cifrado, mac_cifrado, nonce_cifrado = cifrarAES_GCM(engine_aes_KAB, jStr.encode("utf-8"))

# Enviamos el mensaje
print("Envio de paso 6")
socket_Alice_Bob.enviar(mensaje_cifrado)

# Enviamos los mensajes con los nonce y mac que necesita Bob para poder descifrarlo
socket_Alice_Bob.enviar(nonce_cifrado)
socket_Alice_Bob.enviar(mac_cifrado)


############################################
# Paso 7
############################################

# Recibimos el mensaje de Alice
datos_cifrados = socket_Alice_Bob.recibir()
nonce_cifrado = socket_Alice_Bob.recibir()
mac_cifrado = socket_Alice_Bob.recibir()

# Desciframos el mensaje que hemos recibido
datos_descifrados = descifrarAES_GCM(KAB, nonce_cifrado, datos_cifrados, mac_cifrado)

# Decodificamos el contenido del mensaje y lo mostramos 
json_recibido = datos_descifrados.decode("utf-8", "ignore")
print("Paso 7. Bob -> Alice (descifrado): " + json_recibido)

# Extraemos el contenido
DNI = json.loads(json_recibido)


############################################
# Paso 8
############################################

# Preparamos el mensaje para enviar a Bob con mis apellidos
mensaje = "Buenos dias"
jStr = json.dumps(mensaje)

# Volvemos a iniciar el engine de AES para la clave KAB
engine_aes_KAB = iniciarAES_GCM(KAB)

# Ciframos el mensaje con la clave KAB
mensaje_cifrado, mac_cifrado, nonce_cifrado = cifrarAES_GCM(engine_aes_KAB, jStr.encode("utf-8"))

# Enviamos el mensaje
print("Envio de paso 8")
socket_Alice_Bob.enviar(mensaje_cifrado)

# Enviamos los mensajes con los nonce y mac nesarios para poder descifrar
socket_Alice_Bob.enviar(nonce_cifrado)
socket_Alice_Bob.enviar(mac_cifrado)

# Como ya no necesitamos la conexion, la cerramos
socket_Alice_Bob.cerrar()
