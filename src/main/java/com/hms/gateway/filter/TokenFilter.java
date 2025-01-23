package com.hms.gateway.filter;


import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class TokenFilter extends AbstractGatewayFilterFactory<TokenFilter.config> {
    
    public TokenFilter(){
        super(config.class);
    }

    @Override
    public GatewayFilter apply(config config){

        final String SECRET = "6d089bd7d9a07ef33067c58488e2ab9f0aa59a8b712ae5fb0d23d370aa71fb8a895e8cf423598a707a7107d29a58afaf157ab224108891a5a21d9ffa761f1182";

        return (exchange, chain) -> {
            String path = exchange.getRequest().getPath().toString();
            if(path.equals("/user/login") || path.equals("/user/register")){
                return chain.filter(exchange.mutate().request(r->r.header("X-Secret-Key", "SECRET")).build());
            }
            HttpHeaders header = exchange.getRequest().getHeaders();
            if(!header.containsKey(HttpHeaders.AUTHORIZATION)){
                throw new RuntimeException("Authorization Header is missing");
            }

            String authHeader = header.getFirst(HttpHeaders.AUTHORIZATION);
            if(authHeader==null || !authHeader.startsWith("Bearer")){
                throw new RuntimeException("Authorization Header is InValid");
            }

            String token = authHeader.substring(7);
            try{
                Claims claims = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
                exchange = exchange.mutate().request(r->r.header("X-Secrey_key","SECRET")).build();
            } catch(Exception e){
                throw new RuntimeException("Token is Invalid");
            }
            return chain.filter(exchange);
        };
    }

    public static class config {

    }

}
