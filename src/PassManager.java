import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Scanner;
import java.util.Random;

public class PassManager {

    public static String generateRandom(int x){
        RandomStrings random = new RandomStrings(x);
        return random.nextString();

    }
    /*Handles the encryption of files upon closing the program*/
    private static void pass_manager_exit(String inputFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        FileInputStream master = new FileInputStream("MasterPass.txt");
        byte[] master_pass_from_file = master.readAllBytes();
        FileInputStream in = new FileInputStream(inputFile);
        byte[] salt = Arrays.copyOf(master_pass_from_file, 256);
        byte[] filebytes = in.readAllBytes();
        byte[] iv = Arrays.copyOfRange(master_pass_from_file, master_pass_from_file.length-16, master_pass_from_file.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 1000, ivParameterSpec);
        PBEKeySpec keySpec = new PBEKeySpec(Arrays.toString(iv).toCharArray());
        SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
        SecretKey secretKey = kf.generateSecret(keySpec);
        Cipher enc = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
        enc.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
        byte[] encrypted = enc.doFinal(filebytes);
        FileOutputStream out = new FileOutputStream("MasterFile.txt");
        out.write(encrypted);
        out.close();
        master.close();
        in.close();
        File old = new File(inputFile);
        old.delete();
        System.out.println("Goodbye...");
    }
    /*Runs if no exitsting master password file is found upon start up*/
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
        SecureRandom rnd = new SecureRandom();
        byte[] iv = new byte[16];
        rnd.nextBytes(iv);
        try (FileOutputStream output = new FileOutputStream(master_password)){
            output.write(salt);
            output.write(hashed_MasterPass);
            output.write(iv);
            output.flush();
        }

    }
    /*Handles interface and flow of program during execution*/
    private static boolean driver() throws NoSuchProviderException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        System.out.println("Welcome to password manager!");
        String master_password = "";
        String file = "MasterFile.txt";
        Scanner sc = new Scanner(System.in);
        File master_file = new File("MasterFile.txt");
        if (!master_file.exists()){
            System.out.println("You look new! lets set up a master account...");
            first_time_intialize();

            return true;
        }
        else {
            int counter = 0;
            System.out.println("Enter master password:");
            master_password = sc.next();
            while(!checkPass(master_password)){
                System.out.println("INCORRECT! Try again:");
                master_password=sc.next();
                counter++;
                if(counter == 3){
                    System.out.println("Too many wrong attempts. Exiting...");
                    return false;
                }
            }

        }
            return true;}
    /*Checks the entered password against the stored master password*/
    private static boolean checkPass(String entered_master) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileInputStream master = new FileInputStream("MasterPass.txt");
        byte[] master_pass_from_file = master.readAllBytes();
        byte[] salt = Arrays.copyOf(master_pass_from_file, 256);
        master_pass_from_file = Arrays.copyOfRange(master_pass_from_file, 256, master_pass_from_file.length-16);
        KeySpec spec = new PBEKeySpec(entered_master.toCharArray(), salt, 65536, 128);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hashed_entered = f.generateSecret(spec).getEncoded();
        master.close();
        return (Arrays.equals(hashed_entered, master_pass_from_file));
    }
    /* searches master file for password and returns password*/
    private static void get_password(String domain) throws IOException {
        FileReader passwords = new FileReader("MasterFiled.txt");
        Scanner reader = new Scanner(passwords);
        boolean flag = false;
        while(reader.hasNextLine()){
            String data = reader.nextLine();
            if (data.substring(8, 8+domain.length()).equals(domain)){
                System.out.println(data);
                flag = true;
            }
        }
        if (!flag){System.out.println("Account not found for that domain");}
        reader.close();
        passwords.close();
    }
    /*adds an account to the master file*/
    private static void register_account(String domain, String username, int length) throws IOException {
        FileWriter writer = new FileWriter("MasterFiled.txt", true);
        String password = generateRandom(length);
        System.out.println("Your password is: "+password);
        writer.write("Domain: " + domain + " Username: " + username + " Password: " + password + "\n");
        writer.close();
    }
    /*Opens and decrypts the stored master file*/
    private static void open_file(String inputFile) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        FileInputStream master = new FileInputStream("MasterPass.txt");
        byte[] master_pass_from_file = master.readAllBytes();
        FileInputStream in = new FileInputStream(inputFile);
        byte[] salt = Arrays.copyOf(master_pass_from_file, 256);
        byte[] filebytes = in.readAllBytes();
        byte[] iv = Arrays.copyOfRange(master_pass_from_file, master_pass_from_file.length-16, master_pass_from_file.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 1000, ivParameterSpec);
        PBEKeySpec keySpec = new PBEKeySpec(Arrays.toString(iv).toCharArray());
        SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
        SecretKey secretKey = kf.generateSecret(keySpec);
        Cipher enc = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
        enc.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
        byte[] encrypted = enc.doFinal(filebytes);
        FileWriter out = new FileWriter("MasterFiled.txt", true);
        out.write(new String(encrypted, StandardCharsets.UTF_8));
        out.close();
        in.close();
        master.close();

    }
    /* Removes an account from the stored master file*/
    private static void delete_account(String account) throws IOException {
        File input = new File("MasterFiled.txt");
        File temp = new File("Tempfile.txt");
        BufferedWriter writer = new BufferedWriter(new FileWriter(temp));
        BufferedReader reader = new BufferedReader(new FileReader(input));
        String currentLine;
        while((currentLine = reader.readLine())!=null){
            if (currentLine.substring(8, 8+account.length()).equals(account)){
                continue;
            }
            writer.write(currentLine+System.getProperty("line.separator"));
        }
        writer.close();
        reader.close();
        temp.renameTo(input);
    }
    /*Handles main menu during program execution*/
    private static void main_menu() throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        int choice = 0;
        //open_file("MasterFile.txt");
        Scanner sc = new Scanner(System.in);
        System.out.println("1 - Register Account");
        System.out.println("2 - Get Password");
        System.out.println("3 - Delete Account");
        System.out.println("4 - Change Password");
        System.out.println("5 - Exit");
        choice = sc.nextInt();



            switch (choice) {
                case 1:
                    System.out.println("registering account");
                    System.out.println("Please enter the domain name where this account is used:");
                    String domain = sc.next();
                    System.out.println("Please enter your username:");
                    String username = sc.next();
                    System.out.println("How long would you like password to be?:");
                    int length=sc.nextInt();
                    register_account(domain, username, length);
                    break;
                case 2:
                    System.out.println("Enter the domain you would like the password for:");
                    String web = sc.next();
                    get_password(web);
                    break;
                case 3:
                    System.out.println("Enter the domain of the account you wish to delete: ");
                    String account = sc.next();
                    delete_account(account);
                    break;
                case 4:
                    System.out.println("Which domain would you like to change the password for?");
                    String domain1 = sc.next();
                    System.out.println("What is your username on that domain?");
                    String user1 = sc.next();
                    System.out.println("How long you like your new password to be?");
                    int l = sc.nextInt();
                    delete_account(domain1);
                    register_account(domain1,user1,l );
                    break;
                case 5:
                    System.out.println("Exiting...");
                    pass_manager_exit("MasterFiled.txt");
                    System.exit(0);

        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {

        if(driver()){
            open_file("MasterFile.txt");
            while(true) main_menu();
        }
        else{
            System.exit(0);}
    }







}
