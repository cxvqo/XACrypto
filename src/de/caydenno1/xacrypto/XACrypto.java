package de.caydenno1.xacrypto;
import de.caydenno1.xacrypto.hash.sha.SHA0;
public class XACrypto {
    private XACrypto() {}

    static void main(String[] args) {
        String res = SHA0.hash("tah");
        System.out.println(res);
    }
}
