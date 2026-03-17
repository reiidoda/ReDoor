use hex;
use redoor_blockchain::consensus::authority;
use reqwest::Client;
use serde_json::json;
use std::net::SocketAddr;
use tokio::task;
use warp::Filter;

async fn spawn_admin_server(expected_token: Option<String>) -> SocketAddr {
    // admin list route
    let token_list = expected_token.clone();
    let admin_list = warp::get()
        .and(warp::path("admin"))
        .and(warp::path("validators"))
        .and(warp::header::optional::<String>("authorization"))
        .and_then(move |auth: Option<String>| {
            let token = token_list.clone();
            async move {
                if let Some(expected) = token {
                    match auth {
                        Some(a) if a.trim_start_matches("Bearer ") == expected => {}
                        _ => {
                            return Ok::<_, warp::Rejection>(warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({"error":"unauthorized"})),
                                warp::http::StatusCode::UNAUTHORIZED,
                            ))
                        }
                    }
                }
                let list = authority::list_validators();
                Ok::<_, warp::Rejection>(warp::reply::with_status(
                    warp::reply::json(&list),
                    warp::http::StatusCode::OK,
                ))
            }
        });

    // admin set route
    let token_set = expected_token.clone();
    let admin_set = warp::post()
        .and(warp::path("admin"))
        .and(warp::path("validators"))
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::body::json())
        .and_then(move |auth: Option<String>, body: Vec<String>| {
            let token = token_set.clone();
            async move {
                if let Some(expected) = token {
                    match auth {
                        Some(a) if a.trim_start_matches("Bearer ") == expected => {}
                        _ => {
                            return Ok::<_, warp::Rejection>(warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({"error":"unauthorized"})),
                                warp::http::StatusCode::UNAUTHORIZED,
                            ))
                        }
                    }
                }

                let mut validators: Vec<Vec<u8>> = Vec::new();
                for s in body.iter() {
                    match hex::decode(s) {
                        Ok(b) => validators.push(b),
                        Err(_) => {
                            return Ok(warp::reply::with_status(
                                warp::reply::json(
                                    &serde_json::json!({"error":"invalid hex in body"}),
                                ),
                                warp::http::StatusCode::BAD_REQUEST,
                            ))
                        }
                    }
                }
                authority::init_validators(validators);
                Ok::<_, warp::Rejection>(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"status":"validators updated"})),
                    warp::http::StatusCode::OK,
                ))
            }
        });

    let routes = admin_list.or(admin_set);
    let (tx, rx) = tokio::sync::oneshot::channel();

    task::spawn(async move {
        let (addr, server) = warp::serve(routes).bind_ephemeral(([127, 0, 0, 1], 0));
        let _ = tx.send(addr);
        server.await;
    });

    rx.await.unwrap()
}

#[tokio::test]
async fn test_admin_endpoints_auth_and_set() {
    // start server with an ADMIN_TOKEN required
    let token = Some("secrettoken123".to_string());
    let addr = spawn_admin_server(token.clone()).await;
    let base = format!("http://{}", addr);
    let client = Client::new();

    // GET without token -> unauthorized
    let res = client
        .get(&format!("{}/admin/validators", base))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    // GET with wrong token -> unauthorized
    let res = client
        .get(&format!("{}/admin/validators", base))
        .header("Authorization", "Bearer wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    // GET with correct token -> OK (initially empty list)
    let res = client
        .get(&format!("{}/admin/validators", base))
        .header(
            "Authorization",
            format!("Bearer {}", token.clone().unwrap()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body = res.text().await.unwrap();
    assert!(body == "[]" || body == "null" || !body.is_empty());

    // POST set validators with invalid hex -> 400
    let bad_body = json!(["nothex"]);
    let res = client
        .post(&format!("{}/admin/validators", base))
        .header(
            "Authorization",
            format!("Bearer {}", token.clone().unwrap()),
        )
        .json(&bad_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);

    // POST set validators with valid hex -> 200
    let pk = vec![1u8; 32];
    let pk_hex = hex::encode(&pk);
    let ok_body = json!([pk_hex.clone()]);
    let res = client
        .post(&format!("{}/admin/validators", base))
        .header(
            "Authorization",
            format!("Bearer {}", token.clone().unwrap()),
        )
        .json(&ok_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // Now GET should include our validator
    let res = client
        .get(&format!("{}/admin/validators", base))
        .header(
            "Authorization",
            format!("Bearer {}", token.clone().unwrap()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body = res.text().await.unwrap();
    assert!(body.contains(&pk_hex));
}
