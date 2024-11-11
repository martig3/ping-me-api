mod auth_routes;
mod health_routes;
mod notify_routes;
mod user_routes;

use crate::auth::Backend;
use crate::routes::auth_routes::auth_routes;
use crate::routes::user_routes::user_routes;
use crate::AppState;
use axum::Router;
use axum_login::login_required;
use health_routes::health_routes;
use notify_routes::notify_routes;

pub fn routes() -> Router<AppState> {
    Router::new()
        .nest("/user", user_routes())
        .nest("/notify", notify_routes())
        .route_layer(login_required!(Backend))
        .nest("/health", health_routes())
        .nest("/auth", auth_routes())
}
