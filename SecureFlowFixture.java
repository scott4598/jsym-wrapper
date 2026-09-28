package example.wrappertest;

public final class SecureFlowFixture {

    private static String publishedValue;

    private SecureFlowFixture() {
    }

    public static String readSecret() {
        return "classified-value";
    }

    public static void publish(String value) {
        publishedValue = value;
    }

    public static String sanitize(String value) {
        return value == null
                ? ""
                : value.trim().toUpperCase();
    }

    public static void main(String[] args) {
        String secret = readSecret();
        publish(sanitize(secret));
    }
}