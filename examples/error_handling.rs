//! Example demonstrating improved error handling with proper error codes

use http3::{
    error::{Error, Result, ConnectionErrorCode, StreamErrorCode},
    error_context::{ErrorConversion, ResultContext, common_errors, suggest_recovery_strategy},
};

fn process_frame(frame_data: &[u8]) -> Result<()> {
    if frame_data.is_empty() {
        // Use proper error code for frame encoding errors
        return Err(common_errors::frame_encoding_error("Empty frame data"));
    }
    
    if frame_data[0] == 0xFF {
        // Use error context for better debugging
        return Err(Error::Internal("Invalid frame type".to_string()))
            .context("Processing incoming frame")?;
    }
    
    Ok(())
}

fn handle_stream_data(stream_id: u64, data: &[u8]) -> Result<()> {
    // Validate stream ID
    if stream_id > 1000 {
        return Err(common_errors::stream_limit_error(
            format!("Stream ID {} exceeds limit", stream_id)
        ));
    }
    
    // Process frame with context
    process_frame(data)
        .with_context(|| format!("Processing data for stream {}", stream_id))?;
    
    Ok(())
}

fn demonstrate_error_recovery() {
    let errors = vec![
        Error::ConnectionClosed {
            code: ConnectionErrorCode::ProtocolViolation,
            reason: "Invalid packet format".to_string(),
        },
        Error::StreamError {
            code: StreamErrorCode::FlowControlError,
            reason: "Stream limit exceeded".to_string(),
        },
        Error::Timeout,
    ];
    
    for error in errors {
        let strategy = suggest_recovery_strategy(&error);
        println!("Error: {:?}", error);
        println!("Suggested recovery: {:?}", strategy);
        println!();
    }
}

fn main() {
    println!("=== Error Handling Example ===\n");
    
    // Example 1: Frame processing error
    println!("Example 1: Frame processing error");
    match process_frame(&[]) {
        Ok(_) => println!("Frame processed successfully"),
        Err(e) => println!("Error: {}", e),
    }
    println!();
    
    // Example 2: Stream processing with context
    println!("Example 2: Stream processing with context");
    match handle_stream_data(2000, &[0xFF]) {
        Ok(_) => println!("Stream data processed successfully"),
        Err(e) => println!("Error: {}", e),
    }
    println!();
    
    // Example 3: Error recovery strategies
    println!("Example 3: Error recovery strategies");
    demonstrate_error_recovery();
    
    // Example 4: Custom error creation
    println!("Example 4: Custom error creation");
    let custom_error = "Invalid SETTINGS frame".to_connection_error(ConnectionErrorCode::FrameEncodingError);
    println!("Custom error: {:?}", custom_error);
}