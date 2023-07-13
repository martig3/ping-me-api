mod admin_routes;
mod auth_routes;
mod bucket_routes;
mod search_routes;
mod user_routes;
use crate::routes::auth_routes::auth_routes;
use crate::routes::bucket_routes::bucket_routes;
use crate::routes::user_routes::user_routes;
use crate::AppState;
use axum::Router;

use self::admin_routes::admin_routes;
use self::search_routes::search_routes;
pub fn routes() -> Router<AppState> {
    Router::new()
        .nest("/buckets", bucket_routes())
        .nest("/auth", auth_routes())
        .nest("/user", user_routes())
        .nest("/admin", admin_routes())
        .nest("/search", search_routes())
}
