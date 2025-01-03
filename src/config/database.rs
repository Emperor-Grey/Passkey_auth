use sqlx::MySqlPool;
use sqlx::mysql::MySqlPoolOptions;

pub async fn connect_db(db_url: &str) -> MySqlPool {
    MySqlPoolOptions::new()
        .max_connections(5)
        .connect(db_url)
        .await
        .expect("Failed to connect to database")
}
