package example;

public class UserService {
    public String findUserById(String userId) {
        return "user:" + userId;
    }

    public boolean HTTPUserExists(String userId) {
        return findUserById(userId) != null;
    }
}
