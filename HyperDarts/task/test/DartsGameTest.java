import com.google.gson.JsonObject;
import dartsgame.DartsGameApplication;
import org.hyperskill.hstest.dynamic.DynamicTest;
import org.hyperskill.hstest.dynamic.input.DynamicTesting;
import org.hyperskill.hstest.mocks.web.response.HttpResponse;
import org.hyperskill.hstest.stage.SpringTest;
import org.hyperskill.hstest.testcase.CheckResult;
import org.springframework.http.HttpStatus;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;

import java.util.Map;

import static org.hyperskill.hstest.common.JsonUtils.getJson;
import static org.hyperskill.hstest.testing.expect.Expectation.expect;
import static org.hyperskill.hstest.testing.expect.json.JsonChecker.isInteger;
import static org.hyperskill.hstest.testing.expect.json.JsonChecker.isObject;

class TestHint {
  private final String apiPath;
  private final String requestBody;
  private final String message;

  public TestHint(String apiPath, String requestBody, String message) {
    this.apiPath = apiPath;
    this.requestBody = requestBody;
    this.message = message;
  }

  @Override
  public String toString() {
    return "Test case\n" +
            "Testing api: '" + apiPath + '\'' + "\n" +
            (requestBody.length() > 0 ? "request: '" + requestBody + '\'' + "\n" : "") +
            "Expectations: '" + message + "'" + "\n" +
            "-----";
  }
}

public class DartsGameTest extends SpringTest {

  private final String tokenApi = "/oauth/token";

  private String bearerToken = "";
  private final String clientId = "hyperdarts";
  private final String clientSecret = "secret";

  private final String ivanHoe = "{\n" +
          "   \"name\": \"Ivan\",\n" +
          "   \"lastname\": \"Hoe\",\n" +
          "   \"email\": \"ivanhoe@acme.com\",\n" +
          "   \"password\": \"oMoa3VvqnLxW\"\n" +
          "}";

  private final String admin = "{\n" +
          "   \"name\": \"admin\",\n" +
          "   \"lastname\": \"admin\",\n" +
          "   \"email\": \"admin@acme.com\",\n" +
          "   \"password\": \"zy0y3bMvyA6T\"\n" +
          "}";

  private final String robinHood = "{\n" +
          "   \"name\": \"Robin\",\n" +
          "   \"lastname\": \"Hood\",\n" +
          "   \"email\": \"robinhood@acme.com\",\n" +
          "   \"password\": \"ai0y9bMvyF6G\"\n" +
          "}";

  private final String wilhelmTell = "{\n" +
          "   \"name\": \"Wilhelm\",\n" +
          "   \"lastname\": \"Tell\",\n" +
          "   \"email\": \"wilhelmtell@acme.com\",\n" +
          "   \"password\": \"bv0y9bMvyF7E\"\n" +
          "}";

  private final String wrongUser = "{\n" +
          "   \"name\": \"Bobin\",\n" +
          "   \"lastname\": \"Hood\",\n" +
          "   \"email\": \"bobinhood@acme.com\",\n" +
          "   \"password\": \"be0y9bMvyF6G\"\n" +
          "}";


  private final String jwtSigningKey = "-----BEGIN PUBLIC KEY-----\n" +
          "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDQ+7yKlJGuvYtf1soMsJjkQJGA\n" +
          "Xe90QAxqppycf+3JT5ehnvvWtwS8ef+UsqrNa5Rc9tyyHjP7ZXRN145SlRTZzc0d\n" +
          "03Ez10OfAEVdhGACgRxS5s+GZVtdJuVcje3Luq3VIvZ8mV/P4eRcV3yVKDwQEenM\n" +
          "uL6Mh6JLH48KxgbNRQIDAQAB\n" +
          "-----END PUBLIC KEY-----";

  public DartsGameTest() {
    super(DartsGameApplication.class, 28852, "../service_db.mv.db");
  }

  private CheckResult getToken(String user, int status, TestHint hint) {

    System.out.println(hint.toString());

    JsonObject userJson = getJson(user).getAsJsonObject();
    String password = userJson.get("password").getAsString();
    String login = userJson.get("email").getAsString().toLowerCase();

    Map<String, String> urlParams = Map.of("grant_type", "password", "username", login, "password", password);

    HttpResponse response = post("/oauth/token", urlParams)
            .basicAuth(clientId, clientSecret).send();


    if (response.getStatusCode() != status) {
      return CheckResult.wrong("POST " + tokenApi + " should respond with "
              + "status code " + status + ", responded: " + response.getStatusCode() + "\n"
              + response.getStatusCode() + "\n"
              + "Response body:\n" + response.getContent() + "\n"
              + "Request body:\n" + response.getContent());
    }
    String r = response.getContent();

    if (!r.endsWith("}")) {
      r = response.getContent() + "}";
    }
    JsonObject resp = getJson(r).getAsJsonObject();
    bearerToken = resp.get("access_token").getAsString();
    return CheckResult.correct();
  }

  private CheckResult checkToken(String user, TestHint hint) {

    System.out.println(hint.toString());

    JsonObject userJson = getJson(user).getAsJsonObject();
    String login = userJson.get("email").getAsString().toLowerCase();
    Jwt decodedToken;


    try {
      decodedToken = JwtHelper.decode(bearerToken);
    } catch (Exception e) {
      return CheckResult.wrong("Wrong token format!");
    }

    try {
      JwtHelper.decodeAndVerify(bearerToken, new RsaVerifier(jwtSigningKey));
    } catch (Exception e) {
      return CheckResult.wrong("Wrong token signature!");
    }

    expect(decodedToken.getClaims()).asJson().check(
            isObject()
                    .value("client_id", "hyperdarts")
                    .value("user_name", login)
                    .value("scope", new String[] {"read", "write", "update"})
                    .value("exp", isInteger())
                    .value("authorities", login.equals("admin@acme.com") ? new String[] {"ROLE_ADMIN"} : new String[] {"ROLE_GAMER"})
                    .anyOtherValues());

    return CheckResult.correct();
  }


  private CheckResult testTokenApi(String user, String clientId, String clientSecret, int status, TestHint hint) {

    System.out.println(hint.toString());

    JsonObject userJson = getJson(user).getAsJsonObject();
    String password = userJson.get("password").getAsString();
    String login = userJson.get("email").getAsString().toLowerCase();

    Map<String, String> urlParams = Map.of("grant_type", "password", "username", login, "password", password);

    HttpResponse response = post(tokenApi, urlParams)
            .basicAuth(clientId, clientSecret).send();


    if (response.getStatusCode() != status) {
      return CheckResult.wrong("POST " + tokenApi + " should respond with "
              + "status code " + status + ", responded: " + response.getStatusCode() + "\n"
              + response.getStatusCode() + "\n"
              + "Response body:\n" + response.getContent() + "\n"
              + "Request body:\n" + response.getContent());
    }
    return CheckResult.correct();
  }




  @DynamicTest
  DynamicTesting[] dt = new DynamicTesting[]{
          // Negative tests
          () -> testTokenApi(ivanHoe, clientId, "clientSecret", HttpStatus.UNAUTHORIZED.value(),
                  new TestHint(tokenApi, "",
                          "Testing token endpoint with wrong client credentials")),
          () -> testTokenApi(ivanHoe, "clientId", "clientSecret", HttpStatus.UNAUTHORIZED.value(),
                  new TestHint(tokenApi, "",
                          "Testing token endpoint with wrong client credentials")),
          () -> testTokenApi(wrongUser, clientId, clientSecret, HttpStatus.BAD_REQUEST.value(),
                  new TestHint(tokenApi, "",
                          "Testing token endpoint with correct client credentials, but wrong user")),

          // Positive tests
          () -> getToken(ivanHoe, HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user")),
          () -> checkToken(ivanHoe, new TestHint("", "",
                  "Check token")),
          () -> getToken(robinHood, HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user")),
          () -> checkToken(robinHood, new TestHint("", "",
                  "Check token")),
          () -> getToken(wilhelmTell, HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user")),
          () -> checkToken(wilhelmTell, new TestHint("", "",
                  "Check token")),
          () -> getToken(admin, HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user")),
          () -> checkToken(admin, new TestHint("", "",
                  "Check token"))
  };


}