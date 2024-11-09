mod auth_routes;
mod user_routes;

use crate::auth::Backend;
use crate::routes::auth_routes::auth_routes;
use crate::routes::user_routes::user_routes;
use crate::AppState;
use axum::Router;
use axum_login::login_required;

pub fn routes() -> Router<AppState> {
    Router::new()
        .nest("/user", user_routes())
        .route_layer(login_required!(Backend))
        .nest("/auth", auth_routes())
}
