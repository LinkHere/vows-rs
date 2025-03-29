use worker::*;
use serde::{Deserialize, Serialize};

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

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    match req.path().as_str() {
        "/signup" => handle_signup(req).await,
        "/login" => handle_login(req).await,
        _ => Response::error("Not Found", 404),
    }
}

async fn handle_signup(mut req: Request) -> Result<Response> {
    let body: SignupRequest = req.json().await
        .map_err(|e| worker::Error::RustError(format!("Invalid request: {}", e)))?;

    if body.invite_code != "VALID_CODE" {
        return Response::error("Invalid invite code", 403);
    }

    let response = ApiResponse {
        message: "Signup successful!".to_string(),
    };
    Response::from_json(&response)
}

async fn handle_login(mut req: Request) -> Result<Response> {
    let body: LoginRequest = req.json().await
        .map_err(|e| worker::Error::RustError(format!("Invalid request: {}", e)))?;

    if body.username != "admin" || body.password != "password123" {
        return Response::error("Invalid credentials", 403);
    }

    let response = ApiResponse {
        message: "Login successful!".to_string(),
    };
    Response::from_json(&response)
}
