package com.oauth2.client.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.Principal;
import java.util.Map;


@RestController
public class SampleController {
    @GetMapping("/")
    public RestMsg hello() {
        return new RestMsg("Hello world");
    }

    @GetMapping("/api/test")
    public RestMsg apitest() {
        return new RestMsg("Hello apiTest!");
    }

    @GetMapping(value = "/api/hello", produces = "application/json")
    public RestMsg helloUser(OAuth2Authentication auth2Authentication) throws IOException {
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth2Authentication.getDetails();
        Jwt jwt = JwtHelper.decode(details.getTokenValue());
        Map claims = new ObjectMapper().readValue(jwt.getClaims(), Map.class);
        String name = SecurityContextHolder.getContext().getAuthentication().getName();
        return new RestMsg(String.format("Hello '%s' and is customized %b!", name, claims.get("customized")));
    }

    @GetMapping("/api/admin")
    public RestMsg helloAdmin(Principal principal) {
        return new RestMsg(String.format("Welcome '%s'!", principal.getName()));
    }

    private static class RestMsg {
        private String msg;

        public RestMsg(String msg) {
            this.msg = msg;
        }

        public String getMsg() {
            return msg;
        }

        public void setMsg(String msg) {
            this.msg = msg;
        }
    }
}
