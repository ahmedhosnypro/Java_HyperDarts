import java.util.Scanner;

record Player(String username, String email) {

    @Override
    public String username() {
        return username.toUpperCase();
    }

    @Override
    public String email() {
        return email.toLowerCase();
    }
}

class OverrideTest {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        Player player = new Player(scanner.next(), scanner.next());
        System.out.println(player.username() + ":" + player.email());
    }
}