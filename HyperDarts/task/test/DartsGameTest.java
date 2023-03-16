import com.google.gson.JsonObject;
import dartsgame.DartsGameApplication;
import org.hyperskill.hstest.dynamic.DynamicTest;
import org.hyperskill.hstest.dynamic.input.DynamicTesting;
import org.hyperskill.hstest.exception.outcomes.WrongAnswer;
import org.hyperskill.hstest.mocks.web.request.HttpRequest;
import org.hyperskill.hstest.mocks.web.response.HttpResponse;
import org.hyperskill.hstest.stage.SpringTest;
import org.hyperskill.hstest.testcase.CheckResult;
import org.springframework.http.HttpStatus;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import java.util.Map;

import static org.hyperskill.hstest.common.JsonUtils.getJson;
import static org.hyperskill.hstest.mocks.web.constants.Headers.AUTHORIZATION;
import static org.hyperskill.hstest.testing.expect.Expectation.expect;
import static org.hyperskill.hstest.testing.expect.json.JsonChecker.*;

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

  private final String apiCreate = "/api/game/create";
  private final String apiList = "/api/game/list";
  private final String apiJoin = "/api/game/join";
  private final String apiStatus = "/api/game/status";
  private final String apiThrows = "/api/game/throws";
  private final String tokenApi = "/oauth/token";


  private String bearerToken = "";
  private final String clientId = "hyperdarts";
  private final String clientSecret = "secret";

  private final String ivanHoe = """
      {
         "name": "Ivan",
         "lastname": "Hoe",
         "email": "ivanhoe@acme.com",
         "password": "oMoa3VvqnLxW"
      }""";

  private final String robinHood = """
      {
         "name": "Robin",
         "lastname": "Hood",
         "email": "robinhood@acme.com",
         "password": "ai0y9bMvyF6G"
      }""";

  private final String wrongUser = """
      {
         "name": "Bobin",
         "lastname": "Hood",
         "email": "bobinhood@acme.com",
         "password": "be0y9bMvyF6G"
      }""";

  private final String jwtSigningKey = """
      -----BEGIN PUBLIC KEY-----
      MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDQ+7yKlJGuvYtf1soMsJjkQJGA
      Xe90QAxqppycf+3JT5ehnvvWtwS8ef+UsqrNa5Rc9tyyHjP7ZXRN145SlRTZzc0d
      03Ez10OfAEVdhGACgRxS5s+GZVtdJuVcje3Luq3VIvZ8mV/P4eRcV3yVKDwQEenM
      uL6Mh6JLH48KxgbNRQIDAQAB
      -----END PUBLIC KEY-----""";

  public DartsGameTest() {
    super(DartsGameApplication.class, "../service_db.mv.db");
  }

  /**
   * Method for testing api response
   *
   * @param token string representation of bearer token (String)
   * @param body request body (String)
   * @param status expected response status (int)
   * @param api testing api (String)
   * @param method method for api (String)
   * @return response (HttpResponse)
   */
  private HttpResponse checkResponseStatus(String token, String body,
                                           int status, String api, String method) {
    get(api);
    HttpRequest request = switch (method) {
      case "GET" -> get(api);
      case "POST" -> post(api, body);
      case "PUT" -> put(api, body);
      case "DELETE" -> delete(api);
      default -> get(api);
    };

    if (!token.equals("")) {
      String headerValue = "Bearer " + token;
      assert request != null;
      request = request.addHeader(AUTHORIZATION, headerValue);
    }
    HttpResponse response = request.send();

    if (response.getStatusCode() != status) {
      throw new WrongAnswer(method + " " + api  + " should respond with "
              + "status code " + status + ", responded: " + response.getStatusCode() + "\n"
              + "Response body:\n" + response.getContent() + "\n");
    }
    return response;
  }

  private CheckResult testApi(String api, String method, int status, String token, String answer,
                              TestHint hint) {

    System.out.println(hint.toString());

    HttpResponse response = checkResponseStatus(token, "", status, api, method);

    // Check JSON in response
    if (response.getStatusCode() == 200) {
      expect(response.getContent()).asJson().check(
              isObject()
                      .value("status", answer));

    }
    return CheckResult.correct();
  }

  private CheckResult getToken(String user, String scope, int status, TestHint hint) {

    System.out.println(hint.toString());

    JsonObject userJson = getJson(user).getAsJsonObject();
    String password = userJson.get("password").getAsString();
    String login = userJson.get("email").getAsString().toLowerCase();

    Map<String, String> urlParams = Map.of("grant_type", "password", "username", login,
            "password", password, "scope", scope);
    System.out.println("Request params:\n" +
            "Client ID: " + clientId + "\n" +
            "Client password: " + clientSecret + "\n" +
            "User: " + login + "\n" +
            "User password: " + password + "\n" +
            "Scope: " + scope);

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

  private CheckResult checkToken(String user, String[] scope, TestHint hint) {

    System.out.println(hint.toString());

    JsonObject userJson = getJson(user).getAsJsonObject();
    String login = userJson.get("email").getAsString().toLowerCase();
    Jwt decodedToken;


    try {
      decodedToken = JwtHelper.decode(bearerToken);
      System.out.println("Checking token:\n" +
              decodedToken);
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
                    .value("scope", scope)
                    .value("exp", isInteger())
                    .value("authorities", new String[] {"ROLE_GAMER"})
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
                          "Testing token endpoint with wrong client credentials")), // 1
          () -> testTokenApi(ivanHoe, "clientId", "clientSecret", HttpStatus.UNAUTHORIZED.value(),
                  new TestHint(tokenApi, "",
                          "Testing token endpoint with wrong client credentials")), // 2
          () -> testTokenApi(wrongUser, clientId, clientSecret, HttpStatus.BAD_REQUEST.value(),
                  new TestHint(tokenApi, "",
                          "Testing token endpoint with correct client credentials, but wrong user")), // 3
          () -> getToken(ivanHoe, "update", HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user and scope 'update'")), // 4
          () -> checkToken(ivanHoe, new String[] {"update"}, new TestHint(tokenApi, "",
                  "Checking token 'scope' value, it must be - 'update'")), // 5
          () -> testApi(apiCreate, "POST", 403, bearerToken, "ivanhoe@acme.com",
                  new TestHint(apiCreate, "", "The token with the wrong scope (update)" +
                          " should not be able to access api")), // 6
          () -> getToken(ivanHoe, "write", HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user and scope 'write'")), // 7
          () -> checkToken(ivanHoe, new String[] {"write"}, new TestHint(tokenApi, "",
                  "Checking token 'scope' value, it must be - 'write'")), // 8
          () -> testApi(apiList, "GET", 403, bearerToken, "ivanhoe@acme.com",
                  new TestHint(apiList, "", "The token with the wrong scope (write)" +
                          " should not be able to access api with method GET")), // 9
          () -> getToken(ivanHoe, "read", HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user and scope 'read'")), // 10
          () -> checkToken(ivanHoe, new String[] {"read"}, new TestHint(tokenApi, "",
                  "Checking token 'scope' value, it must be - 'read'")), // 11
          () -> testApi(apiCreate, "POST", 403, bearerToken, "ivanhoe@acme.com",
                  new TestHint(apiCreate, "", "The token with the wrong scope (read)" +
                          " should not be able to access api with method POST")), // 12

          // Positive tests
          // api create
          () -> getToken(ivanHoe, "read write", HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user and scope 'read write'")),
          () -> checkToken(ivanHoe, new String[] {"read", "write"}, new TestHint(tokenApi, "",
                  "Checking token 'scope' value, it must be - 'read write'")),
          () -> testApi(apiCreate, "POST", 200, bearerToken, "ivanhoe@acme.com",
                  new TestHint(apiCreate, "", "The token with scope 'read write'" +
                          " should be able to access api with method POST")),
          () -> getToken(robinHood, "read write", HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user and scope 'read write'")),
          () -> checkToken(robinHood, new String[] {"read", "write"}, new TestHint(tokenApi, "",
                  "Checking token 'scope' value, it must be - 'read write'")),
          () -> testApi(apiCreate, "POST", 200, bearerToken, "robinhood@acme.com",
                  new TestHint(apiCreate, "", "The token with scope 'read write'" +
                          " should be able to access api with method GET")),

          // api list
          () -> getToken(robinHood, "read write", HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user and scope 'read write'")),
          () -> checkToken(robinHood, new String[] {"read", "write"}, new TestHint(tokenApi, "",
                  "Checking token 'scope' value, it must be - 'read write'")),
          () -> testApi(apiList, "GET", 200, bearerToken, "robinhood@acme.com",
                  new TestHint(apiList, "", "The token with scope 'read write'" +
                          " should be able to access api with method GET")),
          () -> getToken(robinHood, "read write", HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user and scope 'read write'")),
          () -> checkToken(robinHood, new String[] {"read", "write"}, new TestHint(tokenApi, "",
                  "Checking token 'scope' value, it must be - 'read write'")),
          () -> testApi(apiList, "GET", 200, bearerToken, "robinhood@acme.com",
                  new TestHint(apiList, "", "The token with scope 'read write'" +
                          " should be able to access api with method GET")),

          // api join
          () -> getToken(ivanHoe,"read write", HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user and scope 'read write'")),
          () -> checkToken(ivanHoe, new String[] {"read", "write"}, new TestHint(tokenApi, "",
                  "Checking token 'scope' value, it must be - 'read write'")),
          () -> testApi(apiJoin, "GET", 200, bearerToken, "ivanhoe@acme.com",
                  new TestHint(apiJoin, "", "The token with scope 'read write'" +
                          " should be able to access api with method GET")),
          () -> getToken(robinHood, "read write", HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user and scope 'read write'")),
          () -> checkToken(robinHood, new String[] {"read", "write"}, new TestHint(tokenApi, "",
                  "Checking token 'scope' value, it must be - 'read write'")),
          () -> testApi(apiJoin, "GET", 200, bearerToken, "robinhood@acme.com",
                  new TestHint(apiJoin, "", "The token with scope 'read write'" +
                          " should be able to access api with method GET")),

          // api status
          () -> getToken(robinHood,"read write", HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user and scope 'read write'")),
          () -> checkToken(robinHood, new String[] {"read", "write"}, new TestHint(tokenApi, "",
                  "Checking token 'scope' value, it must be - 'read write'")),
          () -> testApi(apiStatus, "GET", 200, bearerToken, "robinhood@acme.com",
                  new TestHint(apiStatus, "", "The token with scope 'read write'" +
                          " should be able to access api with method GET")),
          () -> getToken(ivanHoe,"read write", HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user and scope 'read write'")),
          () -> checkToken(ivanHoe, new String[] {"read", "write"}, new TestHint(tokenApi, "",
                  "Checking token 'scope' value, it must be - 'read write'")),
          () -> testApi(apiStatus, "GET", 200, bearerToken, "ivanhoe@acme.com",
                  new TestHint(apiStatus, "", "The token with scope 'read write'" +
                          " should be able to access api with method GET")),

          // api throws
          () -> getToken(ivanHoe, "read write", HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user and scope 'read write'")),
          () -> checkToken(ivanHoe, new String[] {"read", "write"}, new TestHint(tokenApi, "",
                  "Checking token 'scope' value, it must be - 'read write'")),
          () -> testApi(apiThrows, "POST", 200, bearerToken, "ivanhoe@acme.com",
                  new TestHint(apiThrows, "", "The token with scope 'read write'" +
                          " should be able to access api with method POST")),
          () -> getToken(robinHood, "read write", HttpStatus.OK.value(), new TestHint(tokenApi, "",
                  "Testing token endpoint with correct credentials and correct user and scope 'read write'")),
          () -> checkToken(robinHood, new String[] {"read", "write"}, new TestHint(tokenApi, "",
                  "Checking token 'scope' value, it must be - 'read write'")),
          () -> testApi(apiThrows, "POST", 200, bearerToken, "robinhood@acme.com",
                  new TestHint(apiThrows, "", "The token with scope 'read write'" +
                          " should be able to access api with method GET")),
  };
}