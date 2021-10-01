# SSL Check

Servicio para chequeo de vigencia de certificados SSL para dominios.

Puerto por defecto: 8093

Parámetros:

```text
-port   Puerto en que escucha el servicio. Debe ser un valor para puertos registrados (1024 – 49151) default: 8093
```

## Endpoints

```text
/
Devuelve la versión del servicio

/service
Devuelve "Running" si el servicio está ejecutando

/days/{host}
Recibe un dominio a chequear. Devuelve el número de días restantes para que caduque el certificado.
```
