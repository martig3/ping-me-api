use std::env;

use crate::auth::{AuthSession, Backend, Credentials};

use axum::extract::Query;

use axum::http::StatusCode;
use axum::response::Redirect;
use axum::{response::IntoResponse, routing::get, Router};

use axum_login::tower_sessions::Session;
use axum_login::{login_required, Error};
use oauth2::CsrfToken;
use serde::Deserialize;
use BackendError::GenericError;

pub const CSRF_STATE_KEY: &str = "oauth.csrf-state";
pub const NEXT_URL_KEY: &str = "auth.next-url";

use crate::errors::BackendError;
use crate::AppState;

#[derive(Debug, Clone, Deserialize)]
pub struct AuthzResp {
    code: String,
    state: CsrfToken,
}

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/logout", get(logout))
        .route_layer(login_required!(Backend))
        .route("/login", get(login))
        .route("/discord/callback", get(callback))
}

pub async fn logout(mut auth_session: AuthSession) -> impl IntoResponse {
    match auth_session.logout().await {
        Ok(_) => Redirect::to("/login").into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn login(auth_session: AuthSession, session: Session) -> impl IntoResponse {
    let (auth_url, csrf_state) = auth_session.backend.authorize_url();

    session
        .insert(CSRF_STATE_KEY, csrf_state.secret())
        .await
        .expect("Serialization should not fail.");

    session
        .insert(NEXT_URL_KEY, "")
        .await
        .expect("Serialization should not fail.");

    Redirect::to(auth_url.as_str()).into_response()
}

pub async fn callback(
    mut auth_session: AuthSession,
    session: Session,
    Query(AuthzResp {
        code,
        state: new_state,
    }): Query<AuthzResp>,
) -> impl IntoResponse {
    let Ok(Some(old_state)) = session.get(CSRF_STATE_KEY).await else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    let creds = Credentials {
        code,
        old_state,
        new_state,
    };

    let user = match auth_session.authenticate(creds).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(GenericError),
        Err(err) => match err {
            Error::Session(session_err) => {
                tracing::debug!("{:?}", session_err);
                Err(GenericError)
            }
            Error::Backend(backend_err) => match backend_err {
                BackendError::NoEmail => Err(BackendError::NoEmail),
                _ => {
                    tracing::debug!("{:?}", backend_err);
                    Err(GenericError)
                }
            },
        },
    };
    let Ok(user) = user else {
        return match user.unwrap_err() {
            BackendError::NoEmail => Redirect::to(
                format!("{}/errors/no-invite", &env::var("CLIENT_BASE_URL").unwrap()).as_str(),
            )
            .into_response(),
            _ => Redirect::to(
                format!("{}/errors/auth", &env::var("CLIENT_BASE_URL").unwrap()).as_str(),
            )
            .into_response(),
        };
    };

    if auth_session.login(&user).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    Redirect::to(format!("{}", env::var("CLIENT_BASE_URL").unwrap()).as_str()).into_response()
}
