use actix_web::{get, App, HttpResponse, HttpServer, Responder};

#[get("/")]
async fn welcome() -> impl Responder {
    HttpResponse::Ok().body("Welcome to Blaz Inject Guard API!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Server starting at http://0.0.0.0:8080");
    
    HttpServer::new(|| {
        App::new()
            .service(welcome)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
