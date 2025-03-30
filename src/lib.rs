use worker::*;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, EncodingKey, Header};

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    match (req.method(), req.path().as_str()) {
        (Method::Options, _) => handle_options(),
        (Method::Post, "/login") => handle_login(req, env).await,
        (Method::Get, "/profile") => handle_profile(req).await,
        _ => Response::error("Not Found", 404),
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    invite_code: String,
}

#[derive(Serialize)]
struct JwtClaims {
    sub: String,
    exp: usize,
}

fn handle_options() -> Result<Response> {
    let mut res = Response::empty()?;
    add_cors_headers(&mut res)?;
    Ok(res)
}

fn generate_jwt(user_id: &str) -> Result<String> {
    let expiration = 3600; // Token valid for 1 hour
    let claims = JwtClaims {
        sub: user_id.to_string(),
        exp: expiration,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(b"secret"))
        .map_err(|e| worker::Error::RustError(e.to_string()))
}

fn cors_headers() -> Headers {
    let mut headers = Headers::new();
    headers.set("Access-Control-Allow-Origin", "*").unwrap();
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS").unwrap();
    headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization").unwrap();
    headers
}

fn add_cors_headers(res: &mut Response) -> Result<()> {
    let headers = cors_headers();
    for (key, value) in headers.entries() {
        res.headers_mut().set(&key, &value)?;
    }
    Ok(())
}

async fn handle_login(mut req: Request, env: Env) -> Result<Response> {
    let body: LoginRequest = req.json().await.map_err(|_| worker::Error::RustError("Invalid request body".to_string()))?;
    let kv = env.kv("INVITE_CODES")?;
    
    let invite_value = kv.get(&body.invite_code).text().await?;
    if invite_value.as_deref() != Some("valid") {
        let mut res = Response::error("Invalid invite code", 403)?;
        add_cors_headers(&mut res)?;
        return Ok(res);
    }
    
    kv.delete(&body.invite_code).await?;
    
    let token = generate_jwt(&body.invite_code)?;
    let mut res = Response::ok(token)?;
    add_cors_headers(&mut res)?;
    Ok(res)
}

async fn handle_profile(_req: Request) -> Result<Response> {
    let mut res = Response::ok("Profile Page")?;
    add_cors_headers(&mut res)?;
    Ok(res)
}
