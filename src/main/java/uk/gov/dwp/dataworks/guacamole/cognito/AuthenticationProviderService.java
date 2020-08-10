package uk.gov.dwp.dataworks.guacamole.cognito;

import com.auth0.jwk.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import com.google.inject.Inject;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.properties.BooleanGuacamoleProperty;
import org.apache.guacamole.properties.StringGuacamoleProperty;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class AuthenticationProviderService {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationProviderService.class);

    static final StringGuacamoleProperty KEYSTORE_URL = new StringGuacamoleProperty() {
        @Override
        public String getName() {
            return "keystore-url";
        }
    };
    static final BooleanGuacamoleProperty VALIDATE_ISSUER = new BooleanGuacamoleProperty() {
        @Override
        public String getName() {
            return "validate-issuer";
        }
    };

    static final StringGuacamoleProperty CLIENT_USERNAME = new StringGuacamoleProperty() {
        @Override
        public String getName() {
            return "client-username";
        }
    };

    static final StringGuacamoleProperty ISSUER = new StringGuacamoleProperty() {
        @Override
        public String getName() {
            return "issuer";
        }
    };

    static final StringGuacamoleProperty CLIENT_PARAMS = new StringGuacamoleProperty() {
        @Override
        public String getName() {
            return "client-params";
        }
    };

    private String keystoreUrl;
    private Boolean validateIssuer;
    private String clientUsername;
    private String clientParams;
    private String issuer;

    private JwkProvider cognito;

    @Inject
    public AuthenticationProviderService(Environment environment) throws GuacamoleException, MalformedURLException, SigningKeyNotFoundException {

        keystoreUrl = environment.getRequiredProperty(KEYSTORE_URL);
        validateIssuer = environment.getRequiredProperty(VALIDATE_ISSUER);
        clientParams = environment.getRequiredProperty(CLIENT_PARAMS);
        clientUsername = environment.getRequiredProperty(CLIENT_USERNAME);
        issuer = environment.getRequiredProperty(ISSUER);

        logger.info("Reading keystore from {}", keystoreUrl);
        JwkProvider provider = new UrlJwkProvider( new URL(keystoreUrl));
        logger.info("Read keystore");

        cognito = new GuavaCachedJwkProvider(provider);
        logger.info("Caching keystore contents");
    }

    public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations(HttpServletRequest request) {

        String token = request.getParameter("token");

        if (token == null) {
            logger.debug("Couldnt read token.");
            return null;
        }

        logger.debug("Get jwt token {}", token);

        // Decode token.
        DecodedJWT decodedToken = JWT.decode(token);

        try {
            Jwk algo = cognito.get(decodedToken.getKeyId());
            Algorithm algorithm;
            switch(algo.getAlgorithm()) {
                case "RS256": algorithm = Algorithm.RSA256((RSAPublicKey) algo.getPublicKey(), null);
                               break;
                case "RS512": algorithm = Algorithm.RSA512((RSAPublicKey) algo.getPublicKey(), null);
                               break;
                default:
                    logger.error("Unsupported JWT algorithm type {}", algo.getType());
                    return null;
            }

            Verification builder = JWT.require(algorithm);
            if (validateIssuer) {
                builder.withIssuer(issuer);
            }
            JWTVerifier verifier = builder.build();
            verifier.verify(token);
        } catch (Exception e) {
            logger.debug("Verify jwt error {}", e.getMessage());
            return null;
        }

        Map<String, Claim> claims = decodedToken.getClaims();
        logger.debug("Get claims {}", claims.values());

        GuacamoleConfiguration config = new GuacamoleConfiguration();

        // CLIENT hostname
        if (request.getParameter("hostname") != null) {
            config.setParameter("hostname", request.getParameter("hostname"));
            logger.debug("Set hostname={}", request.getParameter("hostname"));
        }

        // CLIENT port
        if (request.getParameter("port") != null) {
            config.setParameter("port", request.getParameter("port"));
            logger.debug("Set port={}", request.getParameter("port"));
        }

        // CLIENT protocol
        if (request.getParameter( "protocol" ) != null) {
            config.setProtocol(request.getParameter("protocol"));
            logger.debug("Set protocol={}", request.getParameter("protocol"));
        } else {
            config.setProtocol("vnc");
        }

        if (clientParams != null) {
            String[] parameters = clientParams.split(",");
            for(String p : parameters) {
                String [] parts = p.split("=");
                if (parts.length == 2) {
                    logger.info("Setting property {}={}", parts[0], parts[1]);
                    config.setParameter(parts[0], parts[1]);
                }
            }
        }

        username = Optional.ofNullable(claims.get("preferred_username").orElseGet(Optional.ofNullable(claims.get("cognito:username")).orElse(claims.get("username")).asString();

        if (!username.equals(clientUsername)) {
            logger.warn("Cognito user {} tried to access desktop for {}", username, clientUsername);
            return null;
        }

        String id = Optional.ofNullable(claims.get("sub")).map(Claim::asString).orElse("guest");

        Map<String, GuacamoleConfiguration> configs = new HashMap<String, GuacamoleConfiguration>();
        configs.put(id, config);

        return configs;

    }

}
