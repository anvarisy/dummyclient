package me.anvarisy.dummyclient;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class App {
    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode rootNode = mapper.createObjectNode();
        rootNode.put("pic_id", "anvarisy@gmail.com");
        rootNode.put("merchant_app_id", "com.tokopedia.tkpd");

        ObjectNode metaNode = mapper.createObjectNode();
        metaNode.put("platform", "android/ios");
        metaNode.put("is_rooted", true);
        metaNode.put("is_emulator", false);
        metaNode.put("is_gps_spoof", false);
        metaNode.putArray("signature").add("signature_key").add("signature_key");
        metaNode.put("is_vpn", true);
        metaNode.put("is_clone_app", false);
        metaNode.put("is_screen_sharing", false);
        metaNode.put("is_debug", true);
        metaNode.put("application", "com.tokopedia.marketplace");

        ObjectNode deviceIdNode = mapper.createObjectNode();
        deviceIdNode.put("name", "Samsung");
        deviceIdNode.put("os_version", "Q");
        deviceIdNode.put("series", "A30");
        deviceIdNode.put("cpu", "Mediatek");

        metaNode.set("device_id", deviceIdNode);
        metaNode.putArray("sim_serial").add("abcde12345").add("zyxwv9875");

        ObjectNode geoLocationNode = mapper.createObjectNode();
        geoLocationNode.put("lat", "2.90887363");
        geoLocationNode.put("lng", "4.9099876");

        metaNode.set("geolocation", geoLocationNode);
        String encryptedMeta = null;
        try {
            encryptedMeta = encrypted(metaNode.toString());
            System.out.println(encryptedMeta);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        rootNode.put("meta", encryptedMeta);

        String jsonString = rootNode.toString();
        System.out.println(jsonString);
    }


    private static String encrypt(String jsonString){
        PEMParser pemParser = null;
        try{
            pemParser = new PEMParser(new FileReader("./public_key.pem"));
            PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            PublicKey publicKey = converter.getPublicKey(pemKeyPair.getPublicKeyInfo());
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(jsonString.getBytes(StandardCharsets.UTF_8));
            // Ubah hasil enkripsi menjadi Base64 String dan kembalikan
            return Base64.getEncoder().encodeToString(encryptedBytes);
        }catch(Exception e){
            System.out.println(e.getMessage());
            return "";
        }

    }

    private static String encrypted(String jsonString){
        PublicKey publicKey = readPubKey();
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(jsonString.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    static String readPublicKey(){
        String data;
        try {
            data = new String(Files.readAllBytes(Paths.get("key.pub")));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            data = null;
            e.printStackTrace();
        }
        return data;

    }

    static RSAPublicKey readPubKey(){
        String data;
        try {
            data = new String(Files.readAllBytes(Paths.get("./public_key.pem")));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            data = null;
            e.printStackTrace();
        }
        String publicKeyPEM = data
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END RSA PUBLIC KEY-----", "");
        publicKeyPEM = publicKeyPEM.replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        System.out.println("----------------------");
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            keyFactory = null;
            e.printStackTrace();
        }
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        try {
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            // TODO Auto-generated catch block
            return null;
        }
    }
}
