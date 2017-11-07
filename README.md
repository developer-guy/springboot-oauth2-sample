# Simple Springboot OAuth2 Project

This project contains two applications.One of them oauth2-server and the other oauth2-client.Our oauth2-server project protects the oauth2-client Rest API's.If user want to send requesto to oauth2-client Rest APIs , the user must be authenticate to oauth2-server .

## Getting Started

Before you started you should read these articles because this project was developed by following articles, in these articles explain the OAuth2 and the JWT technologieis :

http://www.tinmegali.com/en/oauth2-using-spring/ _
http://stytex.de/blog/2016/02/01/spring-cloud-security-with-oauth2/

## Running

Firstly , you must run oauth2-server to provide token to users.
Inside OAuth2ServerConfiguration.class you will see the client's credentials, so you can get token like this :

curl -XPOST "trusted-app:webapp@localhost:9091/oauth/token" -d "grant_type=password&username=user&passsword=passsword"

After you get the access token you can send the http request to oauth2-client:

curl -X GET -H "Authorization: Bearer access_token" http://localhost:9090/api/hello --> This request will be work.
curl -X GET -H "Authorization: Bearer access_token" http://localhost:9090/api/admin --> This request will return access_denied error , becuase this user doesn't have ROLE_ADMIN role.

If you want to send request to /api/admin you should login with admin user.

curl -XPOST "trusted-app:webapp@localhost:9091/oauth/token" -d "grant_type=password&username=admin&passsword=passsword"

## Built With

* [Maven](https://maven.apache.org/) - Dependency Management 

## Authors

* **Batuhan Apaydın** - *Initial work* - [PurpleBooth](https://github.com/developer-guy)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Hat tip to anyone who's code was used
* Inspiration
* etc

