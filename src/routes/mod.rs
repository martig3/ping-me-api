mod admin_routes;
mod auth_routes;
mod bucket_routes;
mod buckets_routes;
mod user_routes;

use crate::auth::Backend;
use crate::routes::auth_routes::auth_routes;
use crate::routes::bucket_routes::bucket_routes;
use crate::routes::buckets_routes::buckets_routes;
use crate::routes::user_routes::user_routes;
use crate::AppState;
use axum::Router;
use axum_login::login_required;

use self::admin_routes::admin_routes;
pub fn routes() -> Router<AppState> {
    Router::new()
        .nest("/bucket", bucket_routes())
        .nest("/buckets", buckets_routes())
        .nest("/user", user_routes())
        .nest("/admin", admin_routes())
        .route_layer(login_required!(Backend))
        .nest("/auth", auth_routes())
}
