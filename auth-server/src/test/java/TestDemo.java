import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author DL
 */
public class TestDemo {

    public static void main(String[] args) {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        //String encode = bCryptPasswordEncoder.encode("secret");
        // $2a$10$oCnD3h5gg4ePlbay0Mu1key7Td36pgQiuOiVYf6KDAEfRGif0cQXm
        String encode = bCryptPasswordEncoder.encode("123456");
        System.out.println(encode);
    }
}
