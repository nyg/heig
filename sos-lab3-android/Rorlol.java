public class Rorlol {

    public static void main(String... args) {

        System.out.println(getR());

        String out = "", s = "REALLY";
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 'a' && c <= 'm') {
                c = (char) (c + 13);
            }
            else if (c >= 'A' && c <= 'M') {
                c = (char) (c + 13);
            }
            else if (c >= 'n' && c <= 'z') {
                c = (char) (c - 13);
            }
            else if (c >= 'N' && c <= 'Z') {
                c = (char) (c - 13);
            }
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append(out);
            stringBuilder.append(c);
            out = stringBuilder.toString();
        }

        System.out.println(out);
    }

    public static String getR() {
        String r = "";
        boolean upper = true;
        for (int i = 0; i < 26; i++) {
            StringBuilder stringBuilder;
            if (upper) {
                stringBuilder = new StringBuilder();
                stringBuilder.append(r);
                stringBuilder.append("[A-Z_]");
                r = stringBuilder.toString();
            } else {
                stringBuilder = new StringBuilder();
                stringBuilder.append(r);
                stringBuilder.append("[a-z_]");
                r = stringBuilder.toString();
            }
            upper = !upper;
        }
        return r;
    }
}
