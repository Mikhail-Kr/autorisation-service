# autorisation-service

About:
This is pet project for test keycloak functions in spring boot apps

Get started:
1. run in console 
"docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:22.0.1 start-dev"
2. create your own realm
3. config your keycloak
4. config application.yml according to your keycloak server(url, realms)
5. run app
6. send requests in AuthorizationTestController with bearer token from your keycloak server
(in this example "http://localhost:8080/realms/test/protocol/openid-connect/token" 
with content-type: x-www-form-urlencoded and client_id, client_secret, grant_type = client_credentials)


convention: the product is distributed as is and the developer is not responsible for any problems
that arise during the operation of the program
