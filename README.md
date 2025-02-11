# license-system-final


How the Program Works
1. User Inputs License Details
 .The program asks the user for:
  *The expiry date of the license in YYYY-MM-DD format.
  *The User ID.
.These details are stored in a license file.
2. The License File is Created
 .A text file is created (user provides the filename).
 .The entered license details are written to this file.
3. RSA Key Generation
 .The program generates an RSA private key and saves it to a file (privatekey.pem).
 .The public key extracted from this private key is used for encryption.
4. License File is Encrypted
 .The contents of the license file are encrypted using RSA OAEP encryption.
 .The encrypted data is saved into "Encryptedfile.txt".
5. User Decides Whether to Decrypt
 .The program prompts the user:
  "Do you want to decrypt the file? (Y/N)"
    .If "Y", decryption starts.
    .If "N", the program exits.
6. Decryption and License Validation
 .The user provides the private key file path for decryption.
 .The program:
   .Decrypts Encryptedfile.txt into decryptedfile.txt.
   .Reads the expiry date and checks if it has passed.
   .If the date is valid:
    .The license is accepted, and the contents of the decrypted file are displayed.
   .If the license has expired:
     .Access is denied.
7. File Existence Check (Every 24 Hours)
 .The program checks if the original license file exists.
 .If it does not exist, it notifies the user.
 .The check runs every 10 seconds (should be 24 hours in real-world use).

