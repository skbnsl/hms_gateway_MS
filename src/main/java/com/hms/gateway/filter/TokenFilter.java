package com.hms.gateway.filter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class TokenFilter extends AbstractGatewayFilterFactory<TokenFilter.Config> {
    
    private static final Logger logger = LogManager.getLogger(TokenFilter.class);

    // Secret key for JWT validation
    private static final String SECRET = "6d089bd7d9a07ef33067c58488e2ab9f0aa59a8b712ae5fb0d23d370aa71fb8a895e8cf423598a707a7107d29a58afaf157ab224108891a5a21d9ffa761f1182";

    public TokenFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String path = exchange.getRequest().getPath().toString();
            logger.info("Incoming request path: {}", path);

            // Allow login and registration requests to pass without authentication
            if (path.equals("/user/login") || path.equals("/user/register")) {
                logger.info("Skipping authentication for path: {}", path);
                return chain.filter(exchange.mutate().request(r -> r.header("X-Secret-Key", "SECRET")).build());
            }

            HttpHeaders headers = exchange.getRequest().getHeaders();

            // Check if Authorization header is missing
            if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
                logger.warn("Authorization header is missing in the request.");
                throw new RuntimeException("Authorization Header is missing");
            }

            String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);

            // Validate Authorization header format
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                logger.warn("Invalid Authorization header format. Header: {}", authHeader);
                throw new RuntimeException("Authorization Header is Invalid");
            }

            String token = authHeader.substring(7);
            logger.info("Extracted JWT token: {}", token);

            try {
                // Parse the token
                Claims claims = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
                logger.info("Token successfully validated. User claims: {}", claims);

                // Add custom header for internal communication
                exchange = exchange.mutate().request(r -> r.header("X-Secret-Key", "SECRET")).build();
            } catch (Exception e) {
                logger.error("Token validation failed: {}", e.getMessage());
                throw new RuntimeException("Token is Invalid");
            }

            return chain.filter(exchange);
        };
    }

    // Config class (empty but required)
    public static class Config {
    }
}
