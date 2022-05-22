### Run application

```shell
export MY_PRIVATE_KEY={PRIVATE_KEY_AS_A_RAW_STRING}
export MY_CERT={CERT_AS_A_RAW_STRING}
./gradlew bootRun
```

### Generate private key and certificate as a raw string

*private key*

```shell
openssl genrsa -out private.key 4096
cat private.key | grep -v 'KEY' | tr -d '\n'
```

*certificate*

```shell
openssl req -new -x509 -days 365 -key private.key -out public.crt -subj "/C=FI/ST=Uusimaa/L=Helsinki/O=BigOrganisation/CN=bigorg.com"
cat public.crt | grep -v 'CERTIFICATE' | tr -d '\n'
```

### Authentication

```shell
curl -i -v -XPOST http://localhost:8080/auth -H 'Content-Type: application/json' -d '{"login": "foo", "password": "foo"}'
```

### Request resources

Copy the jwt token that you received in the response from `/auth` and use it in `Authorization` header to request other resources, e.g:

```shell
curl -i -v -XGET http://localhost:8080/jwt -H 'Authorization: Bearer {JWT_TOKEN}'
```