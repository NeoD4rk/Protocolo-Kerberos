##############################################################
# Protocolo Kerberos - Alice
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
clave_priv_alice = crear_RSAKey()

# Y guardamos la clave publica en un fichero .txt
guardar_RSAKey_Publica("clavepublicaAlice.txt", clave_priv_alice)


##########################################
# Paso 1
##########################################

# Creamos la clave simetrica KAT (Alice-TTP)
KAT = crear_AESKey()

# Establecemos la conexion con la TTP
print("Creando conexion con la TTP")
socket_Alice_TTP = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket_Alice_TTP.conectar()

# Creamos el mensaje
mensaje = [] #Array vacio
mensaje.append("Alice") 
mensaje.append(KAT.hex()) # Conversion de Bytes a Hexadecimal
jStr = json.dumps(mensaje) # Covertimos un Array Python a String

# Cargamos la clave publica de la TTP que tenemos guardada en el fichero .txt
publica_ttp = cargar_RSAKey_Publica("clavepublicaTTP.txt")

# Ciframos el mensaje con la clave publica de la TTP obtenida anteriormente
mensaje_cifrado = cifrarRSA_OAEP(jStr, publica_ttp)

# Firmamos la clave KAT
KAT_firmado = firmarRSA_PSS(KAT, clave_priv_alice)

# Creamos el mensaje completo que vamos a enviar
mensaje = [] #Array vacio
mensaje.append(mensaje_cifrado.hex()) 
mensaje.append(KAT_firmado.hex()) # Conversion de Bytes a Hexadecimal
jStr = json.dumps(mensaje) # Covertimos un Array Python a String

# Enviamos el mensaje
print("Envio de paso 1")
socket_Alice_TTP.enviar(jStr.encode("utf-8"))


##########################################
# Paso 3
##########################################

# Creamos un mensaje para enviar a la TTP indicando que queremos comunicarnos con Bob
mensaje = [] #Array vacio
mensaje.append("Alice") 
mensaje.append("Bob") 
jStr = json.dumps(mensaje) # Covertimos un Array Python a String

# Enviamos el mensaje
print("Envio de paso 3")
socket_Alice_TTP.enviar(jStr.encode("utf-8"))


###############################################
#  Paso 4
###############################################

# Esperamos y recibimos la respuesta de la TTP
datos_cifrados = socket_Alice_TTP.recibir()
nonce_cifrado = socket_Alice_TTP.recibir()
mac_cifrado = socket_Alice_TTP.recibir()
nonce_cifrado_bob = socket_Alice_TTP.recibir()
mac_cifrado_bob = socket_Alice_TTP.recibir()

# Desciframos el mensaje que hemos recibido
datos_descifrados = descifrarAES_GCM(KAT, nonce_cifrado, datos_cifrados, mac_cifrado)

# Decodificamos el contenido del mensaje y lo mostramos 
json_recibido = datos_descifrados.decode("utf-8", "ignore")
print("Paso 4. TTP -> Alice (descifrado): " + json_recibido)

# Extraemos el contenido y lo guardamos
ts_ttp, KAB, mensaje_bob_cifrado = json.loads(json_recibido)
KAB = bytearray.fromhex(KAB) # Clave Alice-Bob

# Como no necesitamos ya la conexion con la TTP, cerramos esta conexion
socket_Alice_TTP.cerrar()


#################################################
# Paso 5
#################################################

# Establecemos la conexion con Bob
print("Creando conexion con Bob")
socket_Alice_Bob = SOCKET_SIMPLE_TCP('127.0.0.1', 5553)
socket_Alice_Bob.conectar()

# Iniciamos el engine de cifrado AES para la clave KAB
engine_aes_KAB = iniciarAES_GCM(KAB)

# Creamos el mensaje
mensaje = [] #Array vacio
mensaje.append("Alice") 
mensaje.append(ts_ttp)
jStr = json.dumps(mensaje) # Covertimos un Array Python a String

# Ciframos con la clave KAB
mensaje_cifrado, mac_cifrado, nonce_cifrado = cifrarAES_GCM(engine_aes_KAB, jStr.encode("utf-8"))

# Creamos el mensaje completo
mensaje = [] #Array vacio
mensaje.append(mensaje_bob_cifrado) 
mensaje.append(mensaje_cifrado.hex()) # Conversion de Bytes a Hexadecimal
jStr = json.dumps(mensaje) # Covertimos un Array Python a String

# Enviamos el mensaje
print("Envio de paso 5")
socket_Alice_Bob.enviar(jStr.encode("utf-8"))

# Enviamos los mensajes con los nonce y mac que necesita Bob para poder descifrarlo
socket_Alice_Bob.enviar(nonce_cifrado_bob)
socket_Alice_Bob.enviar(mac_cifrado_bob)
socket_Alice_Bob.enviar(nonce_cifrado)
socket_Alice_Bob.enviar(mac_cifrado)


############################################
# Paso 6
############################################

# Recibimos el mensaje de Bob
datos_cifrados = socket_Alice_Bob.recibir()
nonce_cifrado = socket_Alice_Bob.recibir()
mac_cifrado = socket_Alice_Bob.recibir()

# Desciframos el mensaje que hemos recibido
datos_descifrados = descifrarAES_GCM(KAB, nonce_cifrado, datos_cifrados, mac_cifrado)

# Decodificamos el contenido del mensaje y lo mostramos 
json_recibido = datos_descifrados.decode("utf-8", "ignore")
print("Paso 6. Bob -> Alice (descifrado): " + json_recibido)

# Extraemos el contenido
ts_bob = json.loads(json_recibido)

# Comprobamos si el timestamp es correcto
if(ts_ttp+1 == ts_bob):
    print("El timestamp es correcto")
else:
    print ("El timestamp no es correcto")
    
    # Como hemos detectado que la respuesta al mensaje enviado a Bob no es correcta, podria tratarse de una intrusion o un ataque, por lo que por precaucion cerramos la conexion
    socket_Alice_Bob.cerrar()


############################################
# Paso 7
############################################

# Preparamos el mensaje para enviar a Bob con mi DNI
mensaje = "Lo primero"
jStr = json.dumps(mensaje)

# Volvemos a iniciar el engine de AES para la clave KAB
engine_aes_KAB = iniciarAES_GCM(KAB)

# Ciframos el mensaje con la clave KAB
mensaje_cifrado, mac_cifrado, nonce_cifrado = cifrarAES_GCM(engine_aes_KAB, jStr.encode("utf-8"))

# Enviamos el mensaje
print("Envio de paso 7")
socket_Alice_Bob.enviar(mensaje_cifrado)

# Enviamos los mensajes con los nonce y mac nesarios para poder descifrar
socket_Alice_Bob.enviar(nonce_cifrado)
socket_Alice_Bob.enviar(mac_cifrado)


############################################
# Paso 8
############################################

# Recibimos el mensaje de Bob
datos_cifrados = socket_Alice_Bob.recibir()
nonce_cifrado = socket_Alice_Bob.recibir()
mac_cifrado = socket_Alice_Bob.recibir()
# Desciframos el mensaje que hemos recibido
datos_descifrados = descifrarAES_GCM(KAB, nonce_cifrado, datos_cifrados, mac_cifrado)

# Decodificamos el contenido del mensaje y lo mostramos 
json_recibido = datos_descifrados.decode("utf-8", "ignore")
print("Paso 8. Bob -> Alice (descifrado): " + json_recibido)

# Extraemos el contenido
apellidos = json.loads(json_recibido)
