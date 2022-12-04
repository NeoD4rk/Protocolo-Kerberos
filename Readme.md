Al	principio	(pasos	1	y	2),	tanto	A como	B contactan	con	la	TTP para	enviarle	una	clave	simétrica,	
generada	por	ellos,	que	se	utilizará	para	la	comunicación	posterior.	Tras	esto,	cuando	A	quiera	
comunicarse	con	B mandará	un	mensaje	a	TTP informando	de	ello (paso	3)	y	la	TTP	responderá	
con	 un	 mensaje	 cifrado	 con	 la	 clave	 simétrica	 que	 comparte	 con	 A (paso	 4).	 Este	 mensaje	
contiene,	 entre	 otras	 cosas,	 una	 clave	 de	 sesión	 KAB que	 A y	 B usarán	 para	 comunicarse.	 A	
continuación	(paso	5),	A enviará	a	B un	nuevo	mensaje que	consta	de	dos	elementos,	uno	de	ellos	
ya	cifrado	con	la	clave	de	sesión	KAB y	otro	obtenido	del	mensaje	recibido	en	el	paso	anterior.	B
responde	a	A con	un	nuevo	mensaje	que	contiene	un	valor	de	tiempo	Ts,	recibido	de	A y	TTP al	
que	B suma	1. Finalmente,	si	todo	el	proceso	ha	ido	bien,	A	enviará	a	B	un	mensaje	cifrado	con	
la	clave	de	sesión	KAB que	contiene	el mensaje "Lo primero"	y	B responderá	con	un	mensaje	igualmente	
cifrado	que	contiene	"Buenos días".
