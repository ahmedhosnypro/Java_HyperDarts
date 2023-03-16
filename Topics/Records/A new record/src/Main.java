import java.util.Scanner;

//modify this Record
record Person(String name, String address) {

}

//don't change the code below 
class CheckRecord {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        Person person = new Person(scanner.nextLine(), scanner.nextLine());
        System.out.println(person.name() + " has the address: " + person.address());
    }
}