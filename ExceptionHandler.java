import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
// ... keep your existing imports

// Add this method inside your FileUploadController class
@ExceptionHandler(MaxUploadSizeExceededException.class)
public ResponseEntity<String> handleMaxSizeException(MaxUploadSizeExceededException exc) {
    
    // 1. Initialize your response object (RESBEAN)
    RESBEAN resp = new RESBEAN();
    Gson gson = new Gson();
    
    // 2. Set Error Details
    // Since the request failed before parsing 'jsonData', you likely 
    // won't have the Reference Number or Source ID available here.
    resp.setREQUEST_REFERENCE_NUMBER(null); 
    resp.setSOURCE_ID(null);
    resp.setRESPONSE_STATUS("1");
    
    // Use a specific error code for Size Limit (e.g., create a new one or use a generic one)
    resp.setERROR_CODE("ER_SIZE"); 
    resp.setERROR_DESCRIPTION("File size exceeds the configured maximum limit.");
    
    String finalResponse = gson.toJson(resp);
    
    // 3. Log the error
    logger.error("File upload failed: Size limit exceeded.");
    
    // 4. Return the JSON response with BAD_REQUEST status
    return new ResponseEntity<String>(finalResponse, HttpStatus.BAD_REQUEST);
}

