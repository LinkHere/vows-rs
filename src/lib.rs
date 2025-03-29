use worker::*;
use serde::{Deserialize, Serialize};

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    match req.path().as_str() {
        "/signup" => handle_signup(req, env).await,
        "/login" => handle_login(req, env).await,
        _ => Response::error("Not Found", 404),
    }
}

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

// ✅ Signup: Validate KV Invite Code & Store User in D1
async fn handle_signup(mut req: Request, env: Env) -> Result<Response> {
    //let body: SignupRequest = req.json().await.map_err(|_| Response::error("Invalid request", 400))?;
    let body: SignupRequest = req.json()
    .await
    .map_err(|_| worker::Error::RustError("Invalid request body".to_string()))?;
    let kv = env.kv("INVITE_CODES")?;
    
    // ✅ Check if invite code exists & is "valid"
    let invite_value = kv.get(&body.invite_code).text().await?;
    if invite_value.as_deref() != Some("valid") {
        return Response::error("Invalid invite code", 403);
    }

    // ✅ Remove invite code (one-time use)
    kv.delete(&body.invite_code).await?;

    // ✅ Store user in D1 database
    let db = env.d1("DB")?;
    let query = "INSERT INTO users (username, password) VALUES (?, ?)";
//    db.prepare(query)
//        .bind(&[body.username.into(), body.password.into()])
//        .run()
//        .await
//        .map_err(|_| Response::error("Database error", 500))?;
    let statement = db.prepare(query);
    //.map_err(|e| worker::Error::RustError(e.to_string()))?;
    statement
    .bind(&[body.username.into(), body.password.into()])?
    .run()
    .await
    .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let response = ApiResponse {
        message: "Signup successful!".to_string(),
    };
    Response::from_json(&response)
}

// ✅ Login: Check User in D1
async fn handle_login(mut req: Request, env: Env) -> Result<Response> {
    //let body: LoginRequest = req.json().await.map_err(|_| Response::error("Invalid request", 400))?;
    let body: LoginRequest = req.json()
    .await
    .map_err(|_| worker::Error::RustError("Invalid request body".to_string()))?;
    let db = env.d1("DB")?;

    let query = "SELECT COUNT(*) FROM users WHERE username = ? AND password = ?";
    let result = db.prepare(query)
        .bind(&[body.username.into(), body.password.into()])?
        .first::<i64>(None)
        .await
        //.map_err(|_| Response::error("Database error", 500))?;
        .map_err(|e| worker::Error::RustError(format!("Database error: {}", e)))?;

    if result == Some(1) {
        let response = ApiResponse {
            message: "Login successful!".to_string(),
        };
        Response::from_json(&response)
    } else {
        Response::error("Invalid credentials", 403)
    }
}
