import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Scanner;
import java.util.Random;

public class PassManager {



    public static void pass_manager_exit(){
    System.out.println("Goodbye");
    }

    private static void first_time_intialize() throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        File master_file = new File("MasterFile.txt");
        master_file.createNewFile();
        File master_password = new File("MasterPass.txt");
        master_password.createNewFile();
        System.out.println("Please enter master password:");
        Scanner pass = new Scanner(System.in);
        String masterPassword = pass.next();
        SecureRandom randomgen = SecureRandom.getInstance("SHA1PRNG", "SUN");
        byte[] salt = new byte[256];
        randomgen.nextBytes(salt);
        KeySpec spec = new PBEKeySpec(masterPassword.toCharArray(), salt, 65536, 128);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hashed_MasterPass= f.generateSecret(spec).getEncoded();
        try (FileOutputStream output = new FileOutputStream(master_password)){
            output.write(salt);
            output.write(hashed_MasterPass);
        }




    }

    private static boolean driver() throws NoSuchProviderException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        System.out.println("Welcome to password manager!");
        String master_password = "";
        String file = "MasterFile.txt";
        Scanner sc = new Scanner(System.in);
        File master_file = new File("MasterFile.txt");
        if (master_file.exists()){
            System.out.println("You look new! lets set up a master account...");
            first_time_intialize();
            return true;
        }
        else {
            System.out.println("Enter master password:");
            master_password = sc.next();
            while(!checkPass(master_password)){
                master_password=sc.next();
                System.out.println("INCORRECT! Try again:");
            }

        }
    return true;}

    private static boolean checkPass(String entered_master) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileInputStream master = new FileInputStream("MasterPass.txt");
        byte[] master_pass_from_file = master.readAllBytes();
        byte[] salt = Arrays.copyOf(master_pass_from_file, 256);
        master_pass_from_file = Arrays.copyOfRange(master_pass_from_file, 256, master_pass_from_file.length);
        KeySpec spec = new PBEKeySpec(entered_master.toCharArray(), salt, 65536, 128);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hashed_entered = f.generateSecret(spec).getEncoded();
        return (Arrays.equals(hashed_entered, master_pass_from_file));
    }

    public static void main_menu() {
        int choice = 0;
        Scanner sc = new Scanner(System.in);
        System.out.println("1 - Register Account");
        System.out.println("2 - Get Password");
        System.out.println("3 - Delete Account");
        System.out.println("4 - Exit");
        choice = sc.nextInt();


            switch (choice) {
                case 1:
                    System.out.println("registering account");
                    break;
                case 2:
                    System.out.println("Getting password");
                    break;
                case 3:
                    System.out.println("Deleting Account");
                    break;
                case 4:
                    System.out.println("Exiting...");
                    pass_manager_exit();
                    System.exit(0);

        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
        if(driver()){
        while(true) {
            main_menu();
        }
        }
    }







}
