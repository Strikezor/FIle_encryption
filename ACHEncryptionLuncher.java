package com.tcs.sbi.launcher;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.asn1.cms.ContentInfo;

import com.tcs.sbi.constants.ACHConstants;
import com.tcs.sbi.constants.ErrrorConstants;
import com.tcs.sbi.dbConnection.ACH_Manager;
import com.tcs.sbi.dbConnection.ConnectionManager;
import com.tcs.sbi.main.ACHEncryptionMain;
import com.tcs.sbi.util.ACHEncryptionProperties;
import com.tcs.sbi.util.ACHEncryptionUtility;
import com.tcs.sbi.util.CounterClass;

public class ACHEncryptionLuncher {

	private static final Logger log = LogManager.getLogger(ACHEncryptionLuncher.class);

	private static String sourcePath;
	private static String encryptedBackupPath;
	private static String originalFileBackupPath;
	private static String loggerPath;
	private static String ALLOWED_CHARS;
	private static String pubcertPath;
	private static String privCerPath;
	private static PublicKey pubkey;
	private static PrivateKey privkey;
	private static PGPPrivateKey pgpPrivKey;
	private static PGPPublicKey pgpPubkey;
	private static String NPCICertPath;
	private static X509Certificate ChannelPubCert;
	private static int threadSleepTime;
	private static X509Certificate pubCert;
	private static X509Certificate privCert;
	private static String Encodedpubcert;
	private static String signedFilePath;
	private static PublicKey channelpubKey;
	private static PGPPublicKey channelpgpPubkey;

	private static String duplicateFile;
	private static String txtvalidationFile;
	private static String fileNameValidationFile;

	private static String SignGenerationFailed;
	private static String FileReadingFailed;
	private static String EncryptionProcessFailed;

	private static String sftpHost;
	private static String sftpUsername;
	private static String sftpPwd;
	private static String sftpPort;
	private static String remoteDir;
	private static String archiveDir;
	private static String localDir;
	private static String certPass;
	private static int sftpwaitTime;
	private static String crfilenamestart;
	private static String crfileNameends;
	private static String drfileNameStart;
	private static String drfileNameEnd;

	private static String crdestfilepath;
	private static String drdestfilepath;
	private static String orgndestpathcr;
	private static String orgndestpathdr;
	private static String serverPrivateKeypath;
	
	
	public static String getServerPrivateKeypath() {
		return serverPrivateKeypath;
	}

	public static void setServerPrivateKeypath(String serverPrivateKeypath) {
		ACHEncryptionLuncher.serverPrivateKeypath = serverPrivateKeypath;
	}

	public static String getOrgndestpathcr() {
		return orgndestpathcr;
	}

	public static void setOrgndestpathcr(String orgndestpathcr) {
		ACHEncryptionLuncher.orgndestpathcr = orgndestpathcr;
	}

	public static String getOrgndestpathdr() {
		return orgndestpathdr;
	}

	public static void setOrgndestpathdr(String orgndestpathdr) {
		ACHEncryptionLuncher.orgndestpathdr = orgndestpathdr;
	}
	public static String getCrdestfilepath() {
		return crdestfilepath;
	}

	public static void setCrdestfilepath(String crdestfilepath) {
		ACHEncryptionLuncher.crdestfilepath = crdestfilepath;
	}

	public static String getDrdestfilepath() {
		return drdestfilepath;
	}

	public static void setDrdestfilepath(String drdestfilepath) {
		ACHEncryptionLuncher.drdestfilepath = drdestfilepath;
	}

	private static String dbUser, dbPwd, dbUrl;
	private static int minConn, maxConn, partitionCount, idleMaxAge, idleAgeTestTime;

	private static String destinationFilePath;

	private static String IV, Key;

	public static String getCrfilenamestart() {
		return crfilenamestart;
	}

	public static void setCrfilenamestart(String crfilenamestart) {
		ACHEncryptionLuncher.crfilenamestart = crfilenamestart;
	}

	public static String getCrfileNameends() {
		return crfileNameends;
	}

	public static void setCrfileNameends(String crfileNameends) {
		ACHEncryptionLuncher.crfileNameends = crfileNameends;
	}

	public static String getDrfileNameStart() {
		return drfileNameStart;
	}

	public static void setDrfileNameStart(String drfileNameStart) {
		ACHEncryptionLuncher.drfileNameStart = drfileNameStart;
	}

	public static String getDrfileNameEnd() {
		return drfileNameEnd;
	}

	public static void setDrfileNameEnd(String drfileNameEnd) {
		ACHEncryptionLuncher.drfileNameEnd = drfileNameEnd;
	}

	public static String getDestinationFilePath() {
		return destinationFilePath;
	}

	public static void setDestinationFilePath(String destinationFilePath) {
		ACHEncryptionLuncher.destinationFilePath = destinationFilePath;
	}

	public static int getSftpwaitTime() {
		return sftpwaitTime;
	}

	public static void setSftpwaitTime(int sftpwaitTime) {
		ACHEncryptionLuncher.sftpwaitTime = sftpwaitTime;
	}

	public static String getCertPass() {
		return certPass;
	}

	public static void setCertPass(String certPass) {
		ACHEncryptionLuncher.certPass = certPass;
	}

	public static String getIV() {
		return IV;
	}

	public static void setIV(String iV) {
		IV = iV;
	}

	public static String getKey() {
		return Key;
	}

	public static void setKey(String key) {
		Key = key;
	}

	public static String getDbUser() {
		return dbUser;
	}

	public static void setDbUser(String dbUser) {
		ACHEncryptionLuncher.dbUser = dbUser;
	}

	public static String getDbPwd() {
		return dbPwd;
	}

	public static void setDbPwd(String dbPwd) {
		ACHEncryptionLuncher.dbPwd = dbPwd;
	}

	public static String getDbUrl() {
		return dbUrl;
	}

	public static void setDbUrl(String dbUrl) {
		ACHEncryptionLuncher.dbUrl = dbUrl;
	}

	public static int getMinConn() {
		return minConn;
	}

	public static void setMinConn(int minConn) {
		ACHEncryptionLuncher.minConn = minConn;
	}

	public static int getMaxConn() {
		return maxConn;
	}

	public static void setMaxConn(int maxConn) {
		ACHEncryptionLuncher.maxConn = maxConn;
	}

	public static int getPartitionCount() {
		return partitionCount;
	}

	public static void setPartitionCount(int partitionCount) {
		ACHEncryptionLuncher.partitionCount = partitionCount;
	}

	public static int getIdleMaxAge() {
		return idleMaxAge;
	}

	public static void setIdleMaxAge(int idleMaxAge) {
		ACHEncryptionLuncher.idleMaxAge = idleMaxAge;
	}

	public static int getIdleAgeTestTime() {
		return idleAgeTestTime;
	}

	public static void setIdleAgeTestTime(int idleAgeTestTime) {
		ACHEncryptionLuncher.idleAgeTestTime = idleAgeTestTime;
	}

	public static String getSftpHost() {
		return sftpHost;
	}

	public static void setSftpHost(String sftpHost) {
		ACHEncryptionLuncher.sftpHost = sftpHost;
	}

	public static String getSftpUsername() {
		return sftpUsername;
	}

	public static void setSftpUsername(String sftpUsername) {
		ACHEncryptionLuncher.sftpUsername = sftpUsername;
	}

	public static String getSftpPwd() {
		return sftpPwd;
	}

	public static void setSftpPwd(String sftpPwd) {
		ACHEncryptionLuncher.sftpPwd = sftpPwd;
	}

	public static String getSftpPort() {
		return sftpPort;
	}

	public static void setSftpPort(String sftpPort) {
		ACHEncryptionLuncher.sftpPort = sftpPort;
	}

	public static String getRemoteDir() {
		return remoteDir;
	}

	public static void setRemoteDir(String remoteDir) {
		ACHEncryptionLuncher.remoteDir = remoteDir;
	}

	public static String getArchiveDir() {
		return archiveDir;
	}

	public static void setArchiveDir(String archiveDir) {
		ACHEncryptionLuncher.archiveDir = archiveDir;
	}

	public static String getLocalDir() {
		return localDir;
	}

	public static void setLocalDir(String localDir) {
		ACHEncryptionLuncher.localDir = localDir;
	}

	public static String getSignGenerationFailed() {
		return SignGenerationFailed;
	}

	public static void setSignGenerationFailed(String signGenerationFailed) {
		SignGenerationFailed = signGenerationFailed;
	}

	public static String getFileReadingFailed() {
		return FileReadingFailed;
	}

	public static void setFileReadingFailed(String fileReadingFailed) {
		FileReadingFailed = fileReadingFailed;
	}

	public static String getEncryptionProcessFailed() {
		return EncryptionProcessFailed;
	}

	public static void setEncryptionProcessFailed(String encryptionProcessFailed) {
		EncryptionProcessFailed = encryptionProcessFailed;
	}

	public static String getTxtvalidationFile() {
		return txtvalidationFile;
	}

	public static void setTxtvalidationFile(String txtvalidationFile) {
		ACHEncryptionLuncher.txtvalidationFile = txtvalidationFile;
	}

	public static String getFileNameValidationFile() {
		return fileNameValidationFile;
	}

	public static void setFileNameValidationFile(String fileNameValidationFile) {
		ACHEncryptionLuncher.fileNameValidationFile = fileNameValidationFile;
	}

	public static String getDuplicateFile() {
		return duplicateFile;
	}

	public static void setDuplicateFile(String duplicateFile) {
		ACHEncryptionLuncher.duplicateFile = duplicateFile;
	}

	public static PGPPublicKey getChannelpgpPubkey() {
		return channelpgpPubkey;
	}

	public static void setChannelpgpPubkey(PGPPublicKey channelpgpPubkey) {
		ACHEncryptionLuncher.channelpgpPubkey = channelpgpPubkey;
	}

	public static String getPubcertPath() {
		return pubcertPath;
	}

	public static void setPubcertPath(String pubcertPath) {
		ACHEncryptionLuncher.pubcertPath = pubcertPath;
	}

	public static PublicKey getChannelpubKey() {
		return channelpubKey;
	}

	public static void setChannelpubKey(PublicKey channelpubKey) {
		ACHEncryptionLuncher.channelpubKey = channelpubKey;
	}

	public static String getSignedFilePath() {
		return signedFilePath;
	}

	public static void setSignedFilePath(String signedFilePath) {
		ACHEncryptionLuncher.signedFilePath = signedFilePath;
	}

	public static String getEncodedpubcert() {
		return Encodedpubcert;
	}

	public static void setEncodedpubcert(String encodedpubcert) {
		Encodedpubcert = encodedpubcert;
	}

	public static X509Certificate getPrivCert() {
		return privCert;
	}

	public static void setPrivCert(X509Certificate privCert) {
		ACHEncryptionLuncher.privCert = privCert;
	}

	public static X509Certificate getPubCert() {
		return pubCert;
	}

	public static void setPubCert(X509Certificate pubCert) {
		ACHEncryptionLuncher.pubCert = pubCert;
	}

	public static int getThreadSleepTime() {
		return threadSleepTime;
	}

	public static void setThreadSleepTime(int threadSleepTime) {
		ACHEncryptionLuncher.threadSleepTime = threadSleepTime;
	}

	public static X509Certificate getChannelPubCert() {
		return ChannelPubCert;
	}

	public static void setChannelPubCert(X509Certificate channelPubCert) {
		ChannelPubCert = channelPubCert;
	}

	public static String getNPCICertPath() {
		return NPCICertPath;
	}

	public static void setNPCICertPath(String nPCICertPath) {
		NPCICertPath = nPCICertPath;
	}

	public static String getPrivCerPath() {
		return privCerPath;
	}

	public static void setPrivCerPath(String privCerPath) {
		ACHEncryptionLuncher.privCerPath = privCerPath;
	}

	public static String getALLOWED_CHARS() {
		return ALLOWED_CHARS;
	}

	public static void setALLOWED_CHARS(String aLLOWED_CHARS) {
		ALLOWED_CHARS = aLLOWED_CHARS;
	}

	public static String getSourcePath() {
		return sourcePath;
	}

	public static void setSourcePath(String sourcePath) {
		ACHEncryptionLuncher.sourcePath = sourcePath;
	}

	public static String getLoggerPath() {
		return loggerPath;
	}

	public static void setLoggerPath(String loggerPath) {
		ACHEncryptionLuncher.loggerPath = loggerPath;
	}

	public static Logger getLog() {
		return log;
	}

	public static PublicKey getPubkey() {
		return pubkey;
	}

	public static void setPubkey(PublicKey pubkey) {
		ACHEncryptionLuncher.pubkey = pubkey;
	}

	public static PrivateKey getPrivkey() {
		return privkey;
	}

	public static void setPrivkey(PrivateKey privkey) {
		ACHEncryptionLuncher.privkey = privkey;
	}

	public static PGPPrivateKey getPgpPrivKey() {
		return pgpPrivKey;
	}

	public static void setPgpPrivKey(PGPPrivateKey pgpPrivKey) {
		ACHEncryptionLuncher.pgpPrivKey = pgpPrivKey;
	}

	public static PGPPublicKey getPgpPubkey() {
		return pgpPubkey;
	}

	public static void setPgpPubkey(PGPPublicKey pgpPubkey) {
		ACHEncryptionLuncher.pgpPubkey = pgpPubkey;
	}

	public static String getEncryptedBackupPath() {
		return encryptedBackupPath;
	}

	public static void setEncryptedBackupPath(String encryptedBackupPath) {
		ACHEncryptionLuncher.encryptedBackupPath = encryptedBackupPath;
	}

	public static String getOriginalFileBackupPath() {
		return originalFileBackupPath;
	}

	public static void setOriginalFileBackupPath(String originalFileBackupPath) {
		ACHEncryptionLuncher.originalFileBackupPath = originalFileBackupPath;
	}

	static {

		loggerPath = ACHEncryptionProperties.getInstance().getProperty(ACHConstants.LOGGER_FILEPATH.toString());
		Configurator.initialize(null, loggerPath + ACHConstants.LOGGER_FILENAME.toString() + ".properties");
		sourcePath = ACHEncryptionProperties.getInstance().getProperty("SOURCE_PATH");
		encryptedBackupPath = ACHEncryptionProperties.getInstance().getProperty("DESTINATION_FILES_BACKUP_PATH");
		originalFileBackupPath = ACHEncryptionProperties.getInstance().getProperty("ORIGINAL_FILES_BACKUP_PATH");
		ALLOWED_CHARS = ACHEncryptionProperties.getInstance().getProperty("ALLOWED_CHARS");
		pubcertPath = ACHEncryptionProperties.getInstance().getProperty("PUB_CERT_PATH");
		privCerPath = ACHEncryptionProperties.getInstance().getProperty("PRIV_CERT_PATH");
		NPCICertPath = ACHEncryptionProperties.getInstance().getProperty("NPCI_CERT_PATH");
		threadSleepTime = Integer.parseInt(ACHEncryptionProperties.getInstance().getProperty("Thread_Sleep_Time"));
		signedFilePath = ACHEncryptionProperties.getInstance().getProperty("SIGNED_FILE_PATH");
		duplicateFile = ACHEncryptionProperties.getInstance().getProperty("DUPLICATE_FILE_PATH");
		txtvalidationFile = ACHEncryptionProperties.getInstance().getProperty("TXT_VALIDATION_FAILED_PATH");
		fileNameValidationFile = ACHEncryptionProperties.getInstance().getProperty("FILETYPE_VALIDATION_FAILED_PATH");
		SignGenerationFailed = ACHEncryptionProperties.getInstance().getProperty("SIGN_GENERATION_FAILED_PATH");
		EncryptionProcessFailed = ACHEncryptionProperties.getInstance().getProperty("ENCRYPTION_PROCESS_FAILED_PATH");
		FileReadingFailed = ACHEncryptionProperties.getInstance().getProperty("FILE_READING_FAILED_PATH");
		sftpHost = ACHEncryptionProperties.getInstance().getProperty("SFTP_HOST");
		sftpUsername = ACHEncryptionProperties.getInstance().getProperty("SFTP_USERNAME");
		sftpPort = ACHEncryptionProperties.getInstance().getProperty("SFTP_PORT");
		sftpPwd = ACHEncryptionProperties.getInstance().getProperty("SFTP_PASSWORD");
		remoteDir = ACHEncryptionProperties.getInstance().getProperty("REMOTE_DIR");
		localDir = ACHEncryptionProperties.getInstance().getProperty("LOCAL_DIR");
		archiveDir = ACHEncryptionProperties.getInstance().getProperty("ARCHIVE_DIR");
		dbUser = ACHEncryptionProperties.getInstance().getProperty("dbuser");
		dbUrl = ACHEncryptionProperties.getInstance().getProperty("dburl");
		dbPwd = ACHEncryptionProperties.getInstance().getProperty("dbpwd");
		minConn = Integer.parseInt(ACHEncryptionProperties.getInstance().getProperty("minConn"));
		maxConn = Integer.parseInt(ACHEncryptionProperties.getInstance().getProperty("maxConn"));
		partitionCount = Integer.parseInt(ACHEncryptionProperties.getInstance().getProperty("partitionCount"));
		idleMaxAge = Integer.parseInt(ACHEncryptionProperties.getInstance().getProperty("idleMaxAge"));
		idleAgeTestTime = Integer.parseInt(ACHEncryptionProperties.getInstance().getProperty("idleAgeTestTime"));
		IV = ACHEncryptionProperties.getInstance().getProperty("IV");
		Key = ACHEncryptionProperties.getInstance().getProperty("Key");
		certPass = ACHEncryptionProperties.getInstance().getProperty("CERT_PASSWORD");
		sftpwaitTime = Integer.parseInt(ACHEncryptionProperties.getInstance().getProperty("SFTP_WAIT_TIME"));
		destinationFilePath = ACHEncryptionProperties.getInstance().getProperty("DESTINATION_FILE_PATH");
		crfilenamestart = ACHEncryptionProperties.getInstance().getProperty("CR_FILENAME_START_WITH");
		crfileNameends = ACHEncryptionProperties.getInstance().getProperty("CR_FILENAME_ENDS_WITH");
		drfileNameStart = ACHEncryptionProperties.getInstance().getProperty("DR_FILENAME_START_WITH");
		drfileNameEnd = ACHEncryptionProperties.getInstance().getProperty("DR_FILENAME_ENDS_WITH");
		crdestfilepath = ACHEncryptionProperties.getInstance().getProperty("CR_OUTPUTFILEPATH");
		drdestfilepath = ACHEncryptionProperties.getInstance().getProperty("DR_OUTPUTFILEPATH");
		orgndestpathcr = ACHEncryptionProperties.getInstance().getProperty("ORGN_OUTPUT_CR_PATH"); 
		orgndestpathdr = ACHEncryptionProperties.getInstance().getProperty("ORGN_OUTPUT_DR_PATH");
		serverPrivateKeypath= ACHEncryptionProperties.getInstance().getProperty("SERVER_PRIVATE_KEY_PATH");
		try {
			String password = null;

			Security.addProvider(new BouncyCastleProvider());
			// loaded channel public key from the NPCI shared public certificate
			// and converted public key into PGPPublicKey

			channelpubKey = ACHEncryptionUtility
					.getPubkeyfrompath(ACHEncryptionUtility.aesDecrypt(Key, IV, NPCICertPath));
			channelpgpPubkey = (new JcaPGPKeyConverter().getPGPPublicKey(PGPPublicKey.RSA_GENERAL, channelpubKey,
					new java.util.Date()));

			// loaded Aadesh public and private key from the certificate
			password = ACHEncryptionUtility.aesDecrypt(Key, IV, certPass);
			pubCert = ACHEncryptionUtility.LoadX509Certificate(ACHEncryptionUtility.aesDecrypt(Key, IV, pubcertPath));
			privCert = ACHEncryptionUtility.x509certget(ACHEncryptionUtility.aesDecrypt(Key, IV, privCerPath),
					password);

			privkey = ACHEncryptionUtility.getCertKeys(ACHEncryptionUtility.aesDecrypt(Key, IV, privCerPath), password);

			Encodedpubcert = ACHEncryptionUtility.base64Certificate(ACHEncryptionLuncher.getPubCert());

			ConnectionManager.configureConnPool();

		} catch (RuntimeException | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | PGPException exception) {

			log.info(exception);

		} 

	}

	public static void main(String[] args) {

		log.info(
				"********************************  || AADESH_ACH_CR_DR_ENC UTILITY STARTED ||  ***********************************\n");

		while (true) {

			HashMap<String, Object> decdmap = new HashMap<String, Object>();
			boolean dbupdate = false;
			boolean isfileprocessed = false;
			String referenceNumber = "";

			String fullpath = sourcePath;
			File Filelist = new File(fullpath);
			File[] listOfFiles = Filelist.listFiles();
			log.info("Total Number of File for ACH-CR & DR to be proceed is : " + listOfFiles.length);

			Calendar cal = Calendar.getInstance();
			int dTm = 0;
			cal.add(Calendar.DATE, dTm);
			String currMonth = "";
			String currentDate = "";
			int calMonth = cal.get(Calendar.MONTH) + 1;
			int calYear = cal.get(Calendar.YEAR);
			int calDate = cal.get(Calendar.DATE);
			int maxDays = 0;
			if (calMonth == 13) {
				calMonth = 1;
			}
			currMonth = calMonth + "";
			if (currMonth.length() == 1) {
				currMonth = "0" + calMonth;
			}
			if (calYear % 4 == 0) {
				maxDays = ACHEncryptionUtility.returnMaxDays(calMonth);
				if (calMonth == 2) {
					maxDays = 29;
				}
			} else {
				maxDays = ACHEncryptionUtility.returnMaxDays(calMonth);

			}
			currentDate = (calDate) + "";
			if (Integer.parseInt(currentDate.trim()) <= maxDays) {
				if ((currentDate).length() == 1) {
					currentDate = "0" + (calDate);
				} else {
				}
			} else {
				currentDate = "01";
//				if (currMonth.equals("12")) {
//				} else {
//					int bcurrMonth = Integer.parseInt(currMonth) + 1;
//					if (String.valueOf(bcurrMonth).length() == 1) {
//					} else {
//						String.valueOf(bcurrMonth);
//					}
//				}
			}

			try {
				if (listOfFiles.length > 0) {
//					CounterClass cc = new CounterClass();
//					cc.setCounter(listOfFiles.length);

					ArrayList<String> nameOFFiles = new ArrayList<String>();
					for (File files : listOfFiles) {
						String fileName = files.getName();
						// file extension validation

						referenceNumber = ACHEncryptionUtility.generateRefrenceNumber();

						decdmap.put("FileName", fileName);
						decdmap.put("fileCopiedTime", ACHEncryptionUtility.getTimestamp());
						decdmap.put("RefrenceNumber", referenceNumber);

						if (fileName.contains("-CR-")) {
							decdmap.put("FileType", ErrrorConstants.CR_FILE_TYPE.toString());
						} else if(fileName.contains("-DR-")){
							decdmap.put("FileType", ErrrorConstants.DR_FILE_TYPE.toString());
						} else {
							decdmap.put("FileType", "null");
						}

						isfileprocessed = ACH_Manager.isFilepreviouslyProcessed(fileName, new Date());
						if (!isfileprocessed) {

							if (ACHEncryptionUtility.extensionValidation(fileName) == true) {

								if (fileName.contains(crfilenamestart + currentDate + currMonth + calYear)
										&& (fileName.contains(crfileNameends))
										|| fileName.contains(drfileNameStart + currentDate + currMonth + calYear)
												&& (fileName.contains(drfileNameEnd))) {

									nameOFFiles.add(fileName);
								} else {

									decdmap.put("Status", ErrrorConstants.VALIDATION_FAILED.toString());
									decdmap.put("lastUpdatedtime", ACHEncryptionUtility.getTimestamp());
									decdmap.put("statusDEC", ErrrorConstants.VALIDATION_FAILED.name().toString());
									decdmap.put("totalnoofRecords", "");
									decdmap.put("EncryptionType", "");
									decdmap.put("ERROR_CODE", ErrrorConstants.ER001.name());

									File filetypePath = new File(
											ACHEncryptionLuncher.fileNameValidationFile + currentDate + currMonth + calYear);

									if (!filetypePath.exists()) {
										filetypePath.mkdirs();
									}
									Files.move(Paths.get(fullpath + File.separator + fileName),
											Paths.get(filetypePath + File.separator + fileName),
											StandardCopyOption.REPLACE_EXISTING);
									log.info(
											fileName + " File is not related to ACH_CREDIT & DEBIT hence file is moved "
													);

									dbupdate = ACH_Manager.insertintoAch_CR_logs(decdmap, new Date());
									if (dbupdate == true) {
										log.info("Status updated in DB for File and the Reference Number is : "
												+ referenceNumber);
									} else {

										log.info("Unable to updated in DB for File and the Reference Number is : "
												+ referenceNumber);

									}

								}

							} else {

								decdmap.put("RefrenceNumber", referenceNumber);
								decdmap.put("Status", ErrrorConstants.VALIDATION_FAILED.toString());
								decdmap.put("lastUpdatedtime", ACHEncryptionUtility.getTimestamp());
								decdmap.put("statusDEC", ErrrorConstants.VALIDATION_FAILED.name().toString());
								decdmap.put("totalnoofRecords", "");
								decdmap.put("EncryptionType", "");
								decdmap.put("ERROR_CODE", ErrrorConstants.ER002.name());

								File txtvalidationPath = new File(
										ACHEncryptionLuncher.txtvalidationFile + currentDate + currMonth + calYear);

								if (!txtvalidationPath.exists()) {
									txtvalidationPath.mkdirs();
								}
								Files.move(Paths.get(fullpath + File.separator + fileName),
										Paths.get(txtvalidationPath + File.separator + fileName),
										StandardCopyOption.REPLACE_EXISTING);
								log.info(fileName + " File format is other than txt format hence file moved"
										);
								
								dbupdate = ACH_Manager.insertintoAch_CR_logs(decdmap, new Date());

								if (dbupdate == true) {
									log.info("Status updated in DB for File and the Reference Number is : "
											+ referenceNumber);
								} else {

									log.info("Unable to updated in DB for File and the Reference Number is : "
											+ referenceNumber);
								}
							}

						} else {

							Files.move(Paths.get(fullpath + File.separator + fileName),
									Paths.get(ACHEncryptionLuncher.getDuplicateFile() + File.separator + fileName)
											.normalize(),
									StandardCopyOption.REPLACE_EXISTING);
							log.info("File : " + fileName + " is already Processed, and file is Moved to Path : "
									);
							decdmap.put("RefrenceNumber", referenceNumber);
							decdmap.put("Status", ErrrorConstants.VALIDATION_FAILED.toString());
							decdmap.put("lastUpdatedtime", ACHEncryptionUtility.getTimestamp());
							decdmap.put("statusDEC", ErrrorConstants.VALIDATION_FAILED.name().toString());
							decdmap.put("totalnoofRecords", "");
							decdmap.put("EncryptionType", "");
							decdmap.put("ERROR_CODE", ErrrorConstants.ER003.name());

							dbupdate = ACH_Manager.insertintoAch_CR_logs(decdmap, new Date());
							if (dbupdate == true) {
								log.info("Status updated in DB for File and the Reference Number is : "
										+ referenceNumber);
							} else {

								log.info("Unable to updated in DB for File and the Reference Number is : "
										+ referenceNumber);

							}

						}

					}

					log.info("Number of files to process on :: " + new Date() + " For ACH_CREDIT & DEBIT are: "
							+ nameOFFiles.size());

					try {

						ExecutorService eService = Executors.newSingleThreadExecutor();

						Runnable aadeshMain = new ACHEncryptionMain(nameOFFiles, fullpath, "ACH_CREDIT_MAIN-");
						eService.execute(aadeshMain);
						eService.shutdown();
						while (!eService.isTerminated()) {
							eService.shutdown();
						}

					} catch (NullPointerException e) {
						log.info("Exception while calling main function");
					}

				}

				else {
					log.info("There are no files available to process, hence thread is going to sleep for "+threadSleepTime);
					Thread.sleep(threadSleepTime);
				}

			} catch (IOException e) {

				log.info("Exception in launcher");

			} catch (InterruptedException e) {
				log.info("Exception in launcher");
			} catch (SQLException e) {
				log.info("Exception in launcher");
			} finally {
				log.info("********************************  || AADESH_ACH_CREDIT_ENC UTILITY ENDED ||  ***********************************\n");
			}
		}

	}
}
















































