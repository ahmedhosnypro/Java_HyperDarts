package dartsgame.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/game")
public class ApiController {

    public Map<String, String> status = new HashMap<>();

    @PostMapping("/create")
    public ResponseEntity<?> createGame(Authentication authentication) {
        status.put("status", authentication.getName());
        return ResponseEntity.ok(status);
    }

    @GetMapping("/list")
    public ResponseEntity<?> listGames(Authentication authentication) {
        status.put("status", authentication.getName());
        return ResponseEntity.ok(status);
    }

    @GetMapping("/join")
    public ResponseEntity<?> joinGame(Authentication authentication) {
        status.put("status", authentication.getName());
        return ResponseEntity.ok(status);
    }

    @GetMapping("/status")
    public ResponseEntity<?> getGameStatus(Authentication authentication) {
        status.put("status", authentication.getName());
        return ResponseEntity.ok(status);
    }

    @PostMapping("/throws")
    public ResponseEntity<?> sendThrowsInfo(Authentication authentication) {
        status.put("status", authentication.getName());
        return ResponseEntity.ok(status);
    }

}