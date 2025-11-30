package com.nach.Utils;





import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.nach.main.ACH_CR_Main;

public class ReturnFileGenerator_seq {
	private static final Logger log = LogManager.getLogger(ACH_CR_Main.class);

		//private static final String OUTPUT_FILE_PATH ="E:\\John\\John_Workspace ide\\ACH_NACH\\Z_TEST_OUTPUT\\";
		
	    //private static final String SEQUENCE_FILE_PATH = "E:\\John\\John_Workspace ide\\ACH_NACH\\Z_TEST_OUTPUT\\File_sequence.txt";  //"J:\\W.O.R.K___\\Sample\\Nach\\src\\main\\java\\main\\RETURN_OUTPUT\\sequence.txt";
//    private static final String OUTPUT_FILE_PATH = "J:\\W.O.R.K___\\Sample\\Nach\\src\\main\\java\\main\\RETURN_OUTPUT\\";
//    private static final String SEQUENCE_FILE_PATH = "J:\\W.O.R.K___\\Sample\\Nach\\src\\main\\java\\main\\RETURN_OUTPUT\\sequence.txt";
		private static final SecurePathValidator SecurePath = new SecurePathValidator();
	    private static final String OUTPUT_FILE_PATH_CR = ExtractProperties.getInstance().getExtractProperty("OUTPUT_FILE_PATH_CR");   
	    private static final String SEQUENCE_FILE_PATH_CR = ExtractProperties.getInstance().getExtractProperty("SEQUENCE_FILE_PATH_CR");    
	    private static final String PROCESS_NAME = ExtractProperties.getInstance().getExtractProperty("PROCESS_NAME");
	    private static final String TRANS_TYPE = ExtractProperties.getInstance().getExtractProperty("TRANS_TYPE");
	    private static final String BANK_IDENTIFIER = ExtractProperties.getInstance().getExtractProperty("BANK_IDENTIFIER");
	    private static final String LOGIN_ID = ExtractProperties.getInstance().getExtractProperty("LOGIN_ID");
	    private static final int MAX_SEQUENCE = ExtractProperties.getInstance().getExtractPropertyAsInt("MAX_SEQUENCE");//999999;

    // Method to generate the file with the desired naming structure
    public static String generateReturnFile() throws IOException {
    	
    	if(!SecurePath.validateFilePath(OUTPUT_FILE_PATH_CR) || !SecurePath.validateFilePath(OUTPUT_FILE_PATH_CR)) {
    		return null;
    	}
        // Get the current sequence number from the file
    	log.info("Return file generation started");
        int sequenceNumber = readSequenceNumber();

        // Ensure sequence number is within the valid range
        if (sequenceNumber > MAX_SEQUENCE) {
            sequenceNumber = 1; // Reset to 1 after reaching the maximum value
        }

        // Format the current date as ddMMyyyy
        String currentDate = new SimpleDateFormat("ddMMyyyy").format(new Date());

        // Format the sequence number to a 6-digit number with leading zeros
        String sequence = String.format("%06d", sequenceNumber);

        // Generate the filename according to the specified format
        String fileName = String.format("%s-%s-%s-%s-%s-%s-RTN.txt",
                            PROCESS_NAME, TRANS_TYPE, BANK_IDENTIFIER, LOGIN_ID, currentDate, sequence);

        // Create the file in the specified output path
        File file = new File(OUTPUT_FILE_PATH_CR + fileName);
        boolean b=file.getParentFile().mkdirs(); // Ensure output directory exists
        if(b==true) {
        	log.info("Folder created");
        }
        file.createNewFile(); // Create the file if it does not exist
        log.info("File generated: " + file.getAbsolutePath());

        // Increment and save the updated sequence number back to the file
        saveSequenceNumber(sequenceNumber + 1);
        log.info("return file sequence generated"+file.getAbsolutePath());
        return file.getAbsolutePath(); // Return the full file path
    }

    // Method to read the sequence number from the file
    private static int readSequenceNumber() {
        try {
            // Check if the sequence file exists
            File sequenceFile = new File(SEQUENCE_FILE_PATH_CR);
            if (!sequenceFile.exists()) {
                // If the file doesn't exist, create it with an initial sequence number of 1
                saveSequenceNumber(1);
                return 1;
            }
            // Read the sequence number from the file
            //String sequenceStr = new String(Files.readAllBytes(Paths.get(SEQUENCE_FILE_PATH_CR))).trim();
            String sequenceStr = new String(Files.readAllBytes(Paths.get(SEQUENCE_FILE_PATH_CR)), StandardCharsets.UTF_8).trim();
            return Integer.parseInt(sequenceStr);
        } catch (IOException | NumberFormatException e) {
            log.info("Error while reading secuence number");
            // In case of any error, return 1 as the default sequence number
            return 1;
        }
    }

    // Method to save the updated sequence number to the file
    private static void saveSequenceNumber(int sequenceNumber) {
        try (FileWriter writer = new FileWriter(SEQUENCE_FILE_PATH_CR)) {
            writer.write(String.valueOf(sequenceNumber));
        } catch (IOException e) {
            log.info("Error while saving secuence number");
        }
    }

//    public static void main(String[] args) {
//        try {
//            generateReturnFile();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
}
