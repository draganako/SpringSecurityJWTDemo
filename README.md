# SpringSecurityJWTDemo
Demo RESTful API for demonstrating Spring Security with JWT tokens

The application demonstrates registering, logging in and out, using JWT access and refresh tokens. It exposes both unauthorized routes that don't require an access token - /register, /login and 
authorized routes - /home, /token/refresh, /user (for delete operation), and /logout.

The user can register (with a unique username) and then log in via /register and /login routes, respectively. On login, the user is granted an access and a refresh token. This token must be sent in the Authorization header as 
Bearer <value_of_token> to access the authorized routes.

Users and users' tokens are stored in the PostgreSQL database (in a Docker image). When a user logs out or deletes their account, their tokens change status to expired and revoked.

When accessing authorized routes mentioned above, it is also checked if the user's access/refresh token was revoked - if it was, the user won't be able to access their content.

**How to use**

Make sure to open Docker desktop

Run the following in terminal:\
docker-compose up\
mvn clean install\
mvn spring-boot:run

Try calling both authorized and unauthorized routes. Created tables and their contents can be seen at localhost:8888 with the Adminer tool.

INSERT INTO roles(name) VALUES ('USER'); <br>
INSERT INTO roles(name) VALUES ('ADMIN');

The web application is now available at localhost:8080/home.

