package lt.viko.ad.rdelinda.sifravimas;


import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;



public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        Scanner scanner = new Scanner(System.in);
        boolean continueRunning = true;

        while (continueRunning) {
            System.out.println("Pasirinkite veiksma: 1 - ECB, 2 - CBC," +
                    " 3 - CFB , 4 - OFB , 5 - CTR, " +
                    " 6 - GCM, 7 - Decrypt,  0 - Baigti");
            int choice = scanner.nextInt();
            scanner.nextLine();

            switch (choice) {

                case 1 ->{SecretKey key = generateKey(128);
                    encryptECB(scanner, key);}
                case 2 ->{
                    SecretKey key = generateKey(128);
                    IvParameterSpec iv = generateIv();
                    encryptCBC(scanner, key, iv);
                }
                case 3 ->{
                    SecretKey key = generateKey(128);
                    IvParameterSpec iv = generateIv();
                    encryptCFB(scanner, key, iv);
                }
                case 4 ->{
                    SecretKey key = generateKey(128);
                    IvParameterSpec iv = generateIv();
                    encryptOFB(scanner, key, iv);
                }
                case 5 -> {
                    SecretKey key = generateKey(128);
                    IvParameterSpec iv = generateIv();
                    encryptCTR(scanner, key, iv);
                }
                case 6 ->{
                    SecretKey key = generateKey(128);
                    encryptGCM(scanner, key);
                }
                case 7 -> decrypt(scanner);
                case 0 -> continueRunning = false;
                default -> System.out.println("Netinkamas pasirinkimas.");
            }
        }

        scanner.close();
    }
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
    private static byte[] generateIVForGCM() {
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }
    private static void encryptECB(Scanner scanner, SecretKey key) {
        try {
            System.out.println("Įveskite pradinį tekstą: ");
            String inputText = scanner.nextLine();

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] encryptedBytes = cipher.doFinal(inputText.getBytes());

            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);

            System.out.println("Užšifruotas tekstas: " + encryptedText);
            System.out.println("Naudojamas raktas: " + Base64.getEncoder().encodeToString(key.getEncoded()));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            System.err.println("Klaida šifravimo metu: " + ex.getMessage());
        }
    }


    private static void encryptCBC(Scanner scanner, SecretKey key, IvParameterSpec iv) {
        try {
            System.out.println("Įveskite pradinį tekstą: ");
            String inputText = scanner.nextLine();

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            byte[] encryptedBytes = cipher.doFinal(inputText.getBytes());

            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
            String ivString = Base64.getEncoder().encodeToString(iv.getIV());

            System.out.println("Užšifruotas tekstas: " + encryptedText);
            System.out.println("Naudojamas raktas: " + Base64.getEncoder().encodeToString(key.getEncoded()));
            System.out.println("Naudojamas inicializacijos vektorius (IV): " + ivString);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException |
                 InvalidAlgorithmParameterException ex) {
            System.err.println("Klaida šifravimo metu: " + ex.getMessage());
        }
    }


    private static void encryptCFB(Scanner scanner, SecretKey key, IvParameterSpec iv) {
        try {
            System.out.println("Įveskite pradinį tekstą: ");
            String inputText = scanner.nextLine();

            Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            byte[] encryptedBytes = cipher.doFinal(inputText.getBytes());

            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
            String ivString = Base64.getEncoder().encodeToString(iv.getIV());

            System.out.println("Užšifruotas tekstas: " + encryptedText);
            System.out.println("Naudojamas raktas: " + Base64.getEncoder().encodeToString(key.getEncoded()));
            System.out.println("Naudojamas inicializacijos vektorius (IV): " + ivString);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException |
                 InvalidAlgorithmParameterException ex) {
            System.err.println("Klaida šifravimo metu: " + ex.getMessage());
        }
    }


    private static void encryptOFB(Scanner scanner, SecretKey key, IvParameterSpec iv) {
        try {
            System.out.println("Įveskite pradinį tekstą: ");
            String inputText = scanner.nextLine();

            Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            byte[] encryptedBytes = cipher.doFinal(inputText.getBytes());

            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
            String ivString = Base64.getEncoder().encodeToString(iv.getIV());

            System.out.println("Užšifruotas tekstas: " + encryptedText);
            System.out.println("Naudojamas raktas: " + Base64.getEncoder().encodeToString(key.getEncoded()));
            System.out.println("Naudojamas inicializacijos vektorius (IV): " + ivString);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException |
                 InvalidAlgorithmParameterException ex) {
            System.err.println("Klaida šifravimo metu: " + ex.getMessage());
        }
    }

    private static void encryptCTR(Scanner scanner, SecretKey key, IvParameterSpec iv) {
        try {
            System.out.println("Įveskite pradinį tekstą: ");
            String inputText = scanner.nextLine();

            Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            byte[] encryptedBytes = cipher.doFinal(inputText.getBytes());

            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
            String ivString = Base64.getEncoder().encodeToString(iv.getIV());

            System.out.println("Užšifruotas tekstas: " + encryptedText);
            System.out.println("Naudojamas raktas: " + Base64.getEncoder().encodeToString(key.getEncoded()));
            System.out.println("Naudojamas inicializacijos vektorius (IV): " + ivString);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException |
                 InvalidAlgorithmParameterException ex) {
            System.err.println("Klaida šifravimo metu: " + ex.getMessage());
        }
    }

    private static void encryptGCM(Scanner scanner, SecretKey key) {
        try {
            System.out.println("Įveskite pradinį tekstą: ");
            String inputText = scanner.nextLine();

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = generateIVForGCM();
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

            byte[] encryptedBytes = cipher.doFinal(inputText.getBytes());

            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
            String ivString = Base64.getEncoder().encodeToString(iv);

            System.out.println("Užšifruotas tekstas: " + encryptedText);
            System.out.println("Naudojamas raktas: " + Base64.getEncoder().encodeToString(key.getEncoded()));
            System.out.println("Naudojamas inicializacijos vektorius (IV): " + ivString);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException ex) {
            System.err.println("Klaida šifravimo metu: " + ex.getMessage());
        }
    }


    private static void decrypt(Scanner scanner) {
        try {
            System.out.println("Pasirinkite dešifravimo režimą: 1 - ECB, 2 - CBC," +
                    " 3 - CFB , 4 - OFB , 5 - CTR, " +
                    " 6 - GCM");
            int choice = scanner.nextInt();
            scanner.nextLine();

            System.out.println("Įveskite užšifruotą tekstą: ");
            String encryptedText = scanner.nextLine();

            System.out.println("Įveskite raktą: ");
            String keyString = scanner.nextLine();
            byte[] keyBytes = Base64.getDecoder().decode(keyString);
            SecretKey key = new SecretKeySpec(keyBytes, "AES");

            IvParameterSpec iv = null;
            if (choice == 2 || choice == 3 || choice == 4 || choice == 5) {
                System.out.println("Įveskite inicializacijos vektorių (IV): ");
                String ivString = scanner.nextLine();
                byte[] ivBytes = Base64.getDecoder().decode(ivString);
                iv = new IvParameterSpec(ivBytes);
            }

            switch (choice) {
                case 1 -> decryptECB(encryptedText, key);
                case 2 -> decryptCBC(encryptedText, key, iv);
                case 3 -> decryptCFB(encryptedText, key, iv);
                case 4 -> decryptOFB(encryptedText, key, iv);
                case 5 -> decryptCTR(encryptedText, key, iv);
                case 6 -> decryptGCM(encryptedText, key);
                default -> System.out.println("Netinkamas pasirinkimas.");
            }
        } catch (Exception ex) {
            System.err.println("Klaida dešifravimo metu: " + ex.getMessage());
        }
    }


    private static void decryptGCM(String encryptedText, SecretKey key) {
        try {

            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            byte[] iv = Arrays.copyOfRange(encryptedBytes, 0, 12);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

            byte[] decryptedBytes = cipher.doFinal(Arrays.copyOfRange(encryptedBytes, 12, encryptedBytes.length));

            String decryptedText = new String(decryptedBytes);

            System.out.println("Dešifruotas tekstas: " + decryptedText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException ex) {
            System.err.println("Klaida dešifravimo metu: " + ex.getMessage());
        }
    }


    private static void decryptCTR(String encryptedText, SecretKey key, IvParameterSpec iv) {
        try {
            // Decode Base64 encrypted text
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);

            Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);

            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            String decryptedText = new String(decryptedBytes);

            System.out.println("Dešifruotas tekstas: " + decryptedText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException ex) {
            System.err.println("Klaida dešifravimo metu: " + ex.getMessage());
        }
    }

    private static void decryptOFB(String encryptedText, SecretKey key, IvParameterSpec iv) {
        try {
            // Decode Base64 encrypted text
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);

            Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);

            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            String decryptedText = new String(decryptedBytes);

            System.out.println("Dešifruotas tekstas: " + decryptedText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException ex) {
            System.err.println("Klaida dešifravimo metu: " + ex.getMessage());
        }
    }

    private static void decryptCFB(String encryptedText, SecretKey key, IvParameterSpec iv) {
        try {
            // Decode Base64 encrypted text
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);

            Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);

            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            String decryptedText = new String(decryptedBytes);

            System.out.println("Dešifruotas tekstas: " + decryptedText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException ex) {
            System.err.println("Klaida dešifravimo metu: " + ex.getMessage());
        }
    }


    private static void decryptCBC(String encryptedText, SecretKey key, IvParameterSpec iv) {
        try {
            // Decode Base64 encrypted text
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);

            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            String decryptedText = new String(decryptedBytes);

            System.out.println("Dešifruotas tekstas: " + decryptedText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException ex) {
            System.err.println("Klaida dešifravimo metu: " + ex.getMessage());
        }
    }


    private static void decryptECB(String encryptedText, SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        String decryptedText = new String(decryptedBytes);

        System.out.println("Dešifruotas tekstas: " + decryptedText);
    }
}