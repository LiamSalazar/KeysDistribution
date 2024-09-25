package Chat;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public class AESCriptografo {
    private static final String ALGORITMO = "AES/ECB/PKCS5Padding";
    private SecretKeySpec secretKeySpec;

    public AESCriptografo(String llaveSecreta) throws Exception {
        this.setLlave(llaveSecreta);
    }

    private void setLlave(String myKey) throws Exception {
        byte[] key = myKey.getBytes("UTF-8");
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        key = sha.digest(key);
        key = Arrays.copyOf(key, 16); // usar solo los primeros 128 bits
        this.secretKeySpec = new SecretKeySpec(key, "AES");
    }

    public String desencriptarMensaje(String strToDecrypt) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITMO);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)), "UTF-8");

    }

    public String encriptarMensaje(String strToEncrypt) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITMO);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
    }
}
