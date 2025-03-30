use worker::*;
use serde::{Deserialize, Serialize};

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    if req.method() == Method::Options {
        return handle_preflight();
    }

    let res = match req.path().as_str() {
        "/signup" => handle_signup(req, env).await,
        "/login" => handle_login(req, env).await,
        _ => Response::error("Not Found", 404),
    };

    // Ensure CORS headers are applied to all successful responses
    match res {
        Ok(mut response) => {
            add_cors_headers(&mut response);
            Ok(response)
        }
        Err(e) => {
            let mut error_response = Response::error(format!("Internal error: {}", e), 500)?;
            add_cors_headers(&mut error_response);
            Ok(error_response) // Return a response, not an error
        }
    }
}

// Structs
#[derive(Deserialize)]
struct SignupRequest {
    invite_code: String,
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct ApiResponse {
    message: String,
}

// CORS Headers
// Function to add CORS headers manually
fn add_cors_headers(res: &mut Response) {
    let headers = res.headers_mut();
    headers.set("Access-Control-Allow-Origin", "*").unwrap();
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS").unwrap();
    headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization").unwrap();
}

// Handle CORS Preflight Requests (OPTIONS method)
fn handle_preflight() -> Result<Response> {
    let mut res = Response::empty()?;
    add_cors_headers(&mut res);
    Ok(res)
}

// Example Usage in Signup Handler
async fn handle_signup(mut req: Request, env: Env) -> Result<Response> {
    let body: SignupRequest = req.json()
        .await
        .map_err(|_| worker::Error::RustError("Invalid request body".to_string()))?;

    let kv = env.kv("INVITE_CODES")?;
    let invite_value = kv.get(&body.invite_code).text().await?;

    if invite_value.as_deref() != Some("valid") {
        return Response::error("Invalid invite code", 403);
    }

    kv.delete(&body.invite_code).await?;

    let db = env.d1("DB")?;
    let query = "INSERT INTO users (username, password) VALUES (?, ?)";
    db.prepare(query)
        .bind(&[body.username.into(), body.password.into()])?
        .run()
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let mut res = Response::from_json(&ApiResponse {
        message: "Signup successful!".to_string(),
    })?;
    add_cors_headers(&mut res);
    Ok(res)
}

// Login Handler
async fn handle_login(mut req: Request, env: Env) -> Result<Response> {
    let body: LoginRequest = req.json()
        .await
        .map_err(|_| worker::Error::RustError("Invalid request body".to_string()))?;
    
    let db = env.d1("DB")?;

    let query = "SELECT COUNT(*) as count FROM users WHERE username = ? AND password = ?";
    let result = db.prepare(query)
        .bind(&[body.username.into(), body.password.into()])?
        .first::<serde_json::Value>(None)
        .await
        .map_err(|e| worker::Error::RustError(format!("Database error: {}", e)))?;

    // ✅ Fix: Unwrap `Option<Value>` first
    let count = match result {
        Some(value) => value.get("count").and_then(|v| v.as_i64()).unwrap_or(0),
        None => 0,
    };

    let mut res = if count == 1 {
        let response = ApiResponse {
            message: "Login successful!".to_string(),
        };
        Response::from_json(&response)?
    } else {
        Response::error("Invalid credentials", 403)?
    };

    add_cors_headers(&mut res);
    Ok(res)
}
