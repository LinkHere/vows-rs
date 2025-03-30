use worker::*;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, EncodingKey, Header};
use jsonwebtoken::{decode, DecodingKey, Validation, TokenData};

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    match (req.method(), req.path().as_str()) {
        (Method::Options, _) => handle_options(),
        (Method::Post, "/login") => handle_login(req, env).await,
        (Method::Post, "/update-profile") => handle_update_profile(req, env).await,
        (Method::Get, "/profile") => handle_profile(req).await,
        _ => Response::error("Not Found", 404),
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    invite_code: String,
}

#[derive(Serialize, Deserialize)]  // Add Deserialize here
struct JwtClaims {
    sub: String,
    exp: usize,
}

//#[derive(Serialize)]
//struct JwtClaims {
//    sub: String,
//    exp: usize,
//}

#[derive(Deserialize)]
struct UpdateProfileRequest {
    name: Option<String>,
}

async fn handle_update_profile(mut req: Request, env: Env) -> Result<Response> {
    let token = req.headers().get("Authorization")?.unwrap_or_default();
    let claims = verify_jwt(&token)?;

    let body: UpdateProfileRequest = req.json().await.map_err(|_| worker::Error::RustError("Invalid request body".to_string()))?;
    
    if let Some(name) = body.name {
        let db = env.d1("DB")?;
        let query = "UPDATE users SET name = ? WHERE invite_code = ?";
        db.prepare(query)
            .bind(&[name.into(), claims.sub.into()])?
            .run()
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;
    }

    let mut res = Response::ok("Profile updated successfully")?;
    add_cors_headers(&mut res)?;
    Ok(res)
}

fn verify_jwt(token: &str) -> Result<JwtClaims> {
    let decoding_key = DecodingKey::from_secret(b"secret");
    let token_data: TokenData<JwtClaims> =
        decode::<JwtClaims>(token, &decoding_key, &Validation::default())
            .map_err(|e| worker::Error::RustError(e.to_string()))?;

    Ok(token_data.claims)
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
    
    let db = env.d1("DB")?;
    let query = "INSERT INTO users (invite_code) VALUES (?) ON CONFLICT(invite_code) DO NOTHING";
    db.prepare(query)
        .bind(&[body.invite_code.clone().into()])?
        .run()
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;
    
    let token = generate_jwt(&body.invite_code)?;
    let mut res = Response::ok(token)?;
    add_cors_headers(&mut res)?;
    Ok(res)
}

//async fn handle_profile(_req: Request) -> Result<Response> {
//    let mut res = Response::ok("Profile Page")?;
//    add_cors_headers(&mut res)?;
//    Ok(res)
//}

async fn handle_profile(req: Request) -> Result<Response> {
    let token = match req.headers().get("Authorization")? {
        Some(t) => t.trim_start_matches("Bearer ").to_string(),
        None => return Response::error("Unauthorized", 401),
    };

    let claims = match verify_jwt(&token) {
        Ok(c) => c,
        Err(_) => return Response::error("Invalid token", 403),
    };

    let response = format!("Profile Page - Welcome, {}!", claims.sub);
    let mut res = Response::ok(response)?;
    add_cors_headers(&mut res)?;
    Ok(res)
}
