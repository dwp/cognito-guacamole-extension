package uk.gov.dwp.dataworks.guacamole.cognito;

import com.google.common.io.CharStreams;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import junit.framework.TestCase;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CognitoAuthenticationProviderTest extends TestCase {

    private Environment environment;

    @Before
    public void setUp() throws Exception {
        environment = mock(Environment.class);
        URL testStore = CognitoAuthenticationProviderTest.class.getResource("/store.json");
        when(environment.getRequiredProperty(AuthenticationProviderService.KEYSTORE_URL)).thenReturn("file://" + testStore.getFile());
        when(environment.getRequiredProperty(AuthenticationProviderService.ISSUER)).thenReturn("file://store.json");
        when(environment.getRequiredProperty(AuthenticationProviderService.VALIDATE_ISSUER)).thenReturn(true);
        when(environment.getRequiredProperty(AuthenticationProviderService.CLIENT_USERNAME)).thenReturn("JohnDoe");

    }

    private Injector getInjector() {
        return Guice.createInjector(
                new AbstractModule() {
                    @Override
                    protected void configure() {
                        bind(Environment.class).toInstance(environment);
                    }
                }
        );
    }

    private HttpServletRequest getHttpServletRequest(String token) {
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter("token")).thenReturn(token);
        when(request.getParameter("protocol")).thenReturn("vnc");
        when(request.getParameter("hostname")).thenReturn("192.168.0.12");

        return  request;

    }
    
    @Test
    public void testSuccess() throws IOException {

        String token;
        InputStream inputStream = CognitoAuthenticationProviderTest.class.getResourceAsStream("/jwt.token");
        try (final Reader reader = new InputStreamReader(inputStream)) {
            token = CharStreams.toString(reader);
        }

        HttpServletRequest request = getHttpServletRequest(token);

        Credentials credentials = new Credentials("username","password", request);

        CognitoAuthenticationProvider authProvider = new CognitoAuthenticationProvider(getInjector(), environment);

        Map<String, GuacamoleConfiguration> configs = authProvider.getAuthorizedConfigurations(credentials);

        assertNotNull(configs);
        assertEquals(1, configs.size());
        GuacamoleConfiguration config = configs.get("1234567890");
        assertNotNull(config);
        assertEquals("vnc", config.getProtocol());
        assertEquals("192.168.0.12", config.getParameter("hostname"));
    }

    @Test
    public void testFailure() throws IOException {

        String token;
        InputStream inputStream = CognitoAuthenticationProviderTest.class.getResourceAsStream("/jwt_invalid.token");
        try (final Reader reader = new InputStreamReader(inputStream)) {
            token = CharStreams.toString(reader);
        }

        HttpServletRequest request = getHttpServletRequest(token);

        Credentials credentials = new Credentials("username","password", request);

        CognitoAuthenticationProvider authProvider = new CognitoAuthenticationProvider(getInjector(), environment);

        Map<String, GuacamoleConfiguration> configs = authProvider.getAuthorizedConfigurations(credentials);

        assertNull(configs);
    }

}
